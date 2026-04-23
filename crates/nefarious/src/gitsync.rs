//! Git-backed config synchronisation.
//!
//! Lets an operator roll a network-wide config change by pushing
//! to a git repo — each server periodically fetches and
//! fast-forward-merges the tracked branch of a configured working
//! tree, then, if the HEAD moved, triggers `reload_config()`.
//! Manual trigger via /GITSYNC lets an oper force a sync between
//! scheduled intervals.
//!
//! Uses `git2` (libgit2 bindings) rather than shelling out to the
//! `git` binary: shelling out broke valgrind / leak-tracing in
//! nefarious2 testing because the subprocess's malloc/free pairs
//! confuse the parent's allocator audit. libgit2 runs in-process
//! and honours the same allocator as the rest of the server.
//!
//! Operator owns the repo's auth setup. We look for an SSH agent
//! first, then fall back to anonymous — same default chain libgit2
//! uses for its command-line front-end.
//!
//! Security: the merge is fast-forward only. A force-pushed
//! upstream surfaces as an error instead of silently rewriting our
//! tree. We don't run merge drivers or smudge filters — the working
//! tree is expected to hold a plain config file that we re-read on
//! reload.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{info, warn};

use crate::state::ServerState;

/// Outcome of a sync attempt — the operator-visible summary.
#[derive(Debug)]
pub enum SyncOutcome {
    /// Fast-forward pulled and HEAD moved. `reload` is the
    /// reload_config() summary or an error line.
    Changed {
        old: String,
        new: String,
        reload: String,
    },
    /// Fetched successfully; HEAD didn't move. No reload needed.
    NoChange { head: String },
    /// Anything that went wrong, short enough to drop in a NOTICE.
    Error { message: String },
}

impl SyncOutcome {
    pub fn summary(&self) -> String {
        match self {
            Self::Changed { old, new, reload } => format!(
                "git sync: {}..{} — {reload}",
                short(old),
                short(new),
            ),
            Self::NoChange { head } => {
                format!("git sync: no change (HEAD {})", short(head))
            }
            Self::Error { message } => format!("git sync failed: {message}"),
        }
    }
}

fn short(sha: &str) -> &str {
    &sha[..sha.len().min(8)]
}

/// Format a byte slice as `aa:bb:cc:...` lower-case hex. Matches
/// the fingerprint format libssh2 emits (and nefarious2's
/// gitsync_format_fingerprint).
fn hex_colon(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Tolerant fingerprint compare: case-insensitive, separators
/// stripped. Operators copy-paste these from `ssh-keygen -F` or
/// similar which may use colons or no separator and either case.
fn fingerprint_eq(a: &str, b: &str) -> bool {
    let norm = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .flat_map(|c| c.to_lowercase())
            .collect()
    };
    norm(a) == norm(b)
}

/// One pull-and-maybe-reload cycle. git2 is sync; we run the call
/// on a blocking thread via `spawn_blocking` so the async loop
/// doesn't stall. Result comes back as a SyncOutcome ready for
/// operator display.
pub async fn sync_once(state: Arc<ServerState>) -> SyncOutcome {
    let cfg = state.config.load();
    let path = match cfg.git_config_path() {
        Some(p) => PathBuf::from(p),
        None => {
            return SyncOutcome::Error {
                message: "GIT_CONFIG_PATH not set".into(),
            };
        }
    };

    // Snapshot the knobs the blocking thread needs so we don't
    // hold an ArcSwap guard across an await.
    let ssh_key_path = cfg
        .gitsync_ssh_key()
        .map(String::from)
        .or_else(|| std::env::var("SSL_CERT").ok());
    let pinned_fp = cfg.gitsync_host_fingerprint().map(String::from);
    drop(cfg);

    // Pre-pull TOFU fingerprint (if we've seen the host before).
    let tofu_before = state
        .gitsync_tofu
        .read()
        .ok()
        .and_then(|g| g.clone());

    // Fetch + fast-forward on a blocking thread. The git2 work is
    // synchronous and can block for multiple seconds on a slow
    // remote, so we don't want it on the reactor. The callback
    // captures the observed host-key fingerprint in a shared slot
    // the caller can read after the sync completes.
    let sync_state = Arc::clone(&state);
    let observed_fp: Arc<std::sync::Mutex<Option<(String, String)>>> =
        Arc::new(std::sync::Mutex::new(None));
    let observed_fp_cb = Arc::clone(&observed_fp);
    let pinned_for_cb = pinned_fp.clone();
    let tofu_for_cb = tofu_before.clone();
    let result: Result<(String, String), String> = tokio::task::spawn_blocking(move || {
        sync_repo(
            &path,
            ssh_key_path.as_deref(),
            pinned_for_cb.as_deref(),
            tofu_for_cb,
            observed_fp_cb,
        )
    })
    .await
    .unwrap_or_else(|e| Err(format!("join error: {e}")));

    // If the fetch succeeded and we saw a host fingerprint that
    // wasn't already pinned, store it as the TOFU anchor for
    // future pulls.
    if result.is_ok() {
        if let Some((host, fp)) = observed_fp.lock().ok().and_then(|g| g.clone()) {
            let already_pinned = pinned_fp.is_some();
            let already_tofu = tofu_before.as_ref().map(|t| &t.fingerprint) == Some(&fp);
            if !already_pinned && !already_tofu {
                if let Ok(mut slot) = state.gitsync_tofu.write() {
                    *slot = Some(crate::state::GitsyncTofu { host, fingerprint: fp });
                }
            }
        }
    }

    match result {
        Err(e) => SyncOutcome::Error { message: e },
        Ok((old, new)) if old == new => SyncOutcome::NoChange { head: new },
        Ok((old, new)) => {
            // Two potential side effects once HEAD has moved: the
            // config itself may have changed (→ reload_config),
            // and a TLS cert file in the repo may have changed
            // (→ install it and reload the SslAcceptor). Both run
            // independently; a failure in one doesn't block the
            // other.
            let reload = match sync_state.reload_config() {
                Ok(s) => s,
                Err(e) => format!("reload failed: {e}"),
            };
            let cert_note = match install_cert_if_configured(&sync_state) {
                Ok(Some(msg)) => format!(", {msg}"),
                Ok(None) => String::new(),
                Err(e) => format!(", cert install failed: {e}"),
            };
            SyncOutcome::Changed {
                old,
                new,
                reload: format!("{reload}{cert_note}"),
            }
        }
    }
}

/// If GITSYNC_CERT_PATH is set, look up that file in the synced
/// working tree, validate it as PEM, and atomically replace the
/// running certfile. Triggers `state.reload_ssl()` on success so
/// new connections pick up the rotated cert immediately. Returns
/// `Ok(None)` when cert sync isn't configured, `Ok(Some(note))`
/// on a successful install/reload or "unchanged" skip, and
/// `Err(reason)` on any validation or I/O failure.
fn install_cert_if_configured(state: &Arc<ServerState>) -> Result<Option<String>, String> {
    let cfg = state.config.load();
    let repo_root = match cfg.git_config_path() {
        Some(p) => PathBuf::from(p),
        None => return Ok(None),
    };
    let repo_cert_rel = match cfg.gitsync_cert_path() {
        Some(p) => p.to_string(),
        None => return Ok(None),
    };
    let dest = match cfg.gitsync_cert_file() {
        Some(p) => PathBuf::from(p),
        None => {
            return Err(
                "GITSYNC_CERT_PATH set but GITSYNC_CERT_FILE / SSL_CERTFILE missing".into(),
            );
        }
    };
    drop(cfg);

    let src = repo_root.join(&repo_cert_rel);
    let content = std::fs::read(&src)
        .map_err(|e| format!("read {}: {e}", src.display()))?;

    if !looks_like_pem(&content) {
        return Err(format!(
            "rejected: {} doesn't look like a PEM certificate",
            src.display()
        ));
    }

    // Skip the disk churn if on-disk content already matches.
    if let Ok(existing) = std::fs::read(&dest) {
        if existing == content {
            return Ok(Some(format!("cert unchanged ({})", dest.display())));
        }
    }

    // Write atomically: temp file next to the target, then rename.
    // The rename is the point at which any running TLS handshake
    // that reads the file would see the new content — which it
    // doesn't, since openssl snapshots on acceptor build, so the
    // window is safe.
    let tmp = dest.with_extension("new");
    let bak = dest.with_extension("backup");
    std::fs::write(&tmp, &content).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    // Best-effort backup of the existing cert so an operator can
    // roll back by hand if the new one misbehaves.
    if dest.exists() {
        let _ = std::fs::remove_file(&bak);
        let _ = std::fs::rename(&dest, &bak);
    }
    std::fs::rename(&tmp, &dest)
        .map_err(|e| format!("rename {} → {}: {e}", tmp.display(), dest.display()))?;

    // Hot-swap the acceptor so new handshakes use the new cert.
    state
        .reload_ssl()
        .map_err(|e| format!("cert installed but SSL reload failed: {e}"))?;

    Ok(Some(format!("cert rotated ({})", dest.display())))
}

/// Cheap PEM sanity check — content starts with a BEGIN
/// CERTIFICATE banner. We don't fully parse x509 here; openssl
/// will reject anything bogus on the next acceptor build, and the
/// reload returns an error at that point.
fn looks_like_pem(content: &[u8]) -> bool {
    let haystack = std::str::from_utf8(content).unwrap_or("");
    haystack.contains("-----BEGIN CERTIFICATE-----")
}

/// Synchronous git2 entry point — open the repo, fetch origin for
/// the current branch, fast-forward-merge. Returns `(old_head,
/// new_head)` shas on success. String errors so we can shuttle the
/// message across the blocking boundary without fighting Send.
///
/// `ssh_key` is the path libssh2 should load as the private key.
/// Matches nefarious2 gitsync.c's scheme: operator configures
/// `GITSYNC_SSH_KEY` explicitly, or we fall back to the server's
/// TLS certfile (which ships a PEM key that libssh2 accepts).
///
/// `pinned_fp` is an operator-provided SSH host-key fingerprint;
/// when present the remote MUST match it exactly. `tofu` is the
/// fingerprint we captured on the previous successful pull;
/// serves as a softer contract when no pin is configured. Any new
/// fingerprint observed during this call is written into
/// `observed_fp_out` so the caller can update the TOFU anchor.
fn sync_repo(
    path: &Path,
    ssh_key: Option<&str>,
    pinned_fp: Option<&str>,
    tofu: Option<crate::state::GitsyncTofu>,
    observed_fp_out: Arc<std::sync::Mutex<Option<(String, String)>>>,
) -> Result<(String, String), String> {
    use git2::{AutotagOption, CertificateCheckStatus, FetchOptions, RemoteCallbacks, Repository};

    let repo = Repository::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;

    let head = repo.head().map_err(|e| format!("head: {e}"))?;
    let branch_name = head
        .shorthand()
        .ok_or_else(|| "HEAD is not on a branch".to_string())?
        .to_string();
    let old_sha = head
        .target()
        .ok_or_else(|| "HEAD has no target".to_string())?
        .to_string();

    // Find the configured upstream for the current branch.
    let upstream_name = {
        let config = repo.config().map_err(|e| format!("config: {e}"))?;
        config
            .get_string(&format!("branch.{branch_name}.remote"))
            .map_err(|_| format!("branch {branch_name} has no upstream remote"))?
    };
    let mut remote = repo
        .find_remote(&upstream_name)
        .map_err(|e| format!("remote {upstream_name}: {e}"))?;

    // Build credential + certificate callbacks.
    let ssh_key_owned = ssh_key.map(|s| s.to_string());
    let pinned_fp_owned = pinned_fp.map(|s| s.to_string());
    let tofu_owned = tofu.clone();

    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(move |_url, username_from_url, allowed_types| {
        if allowed_types.is_ssh_key() {
            let user = username_from_url.unwrap_or("git");
            if let Some(ref key) = ssh_key_owned {
                // PEM files contain the private key inline; libssh2
                // can derive the public half, so we don't need a
                // separate .pub path.
                return git2::Cred::ssh_key(user, None, Path::new(key), None);
            }
            if let Ok(cred) = git2::Cred::ssh_key_from_agent(user) {
                return Ok(cred);
            }
        }
        git2::Cred::default()
    });

    // SSH host-key verification with TOFU semantics. libgit2 gives
    // us the observed cert; we format its hash as colon-hex and
    // either accept (first sighting), confirm (known), or reject
    // (mismatch). HTTPS certs pass through unchanged.
    callbacks.certificate_check(move |cert, host| {
        if let Some(hostkey) = cert.as_hostkey() {
            let fp = if let Some(h) = hostkey.hash_sha256() {
                hex_colon(h)
            } else if let Some(h) = hostkey.hash_sha1() {
                hex_colon(h)
            } else {
                return Err(git2::Error::from_str("unknown SSH host-key hash"));
            };

            // Capture the observed fingerprint for the outer
            // caller, who may promote it to the TOFU slot after
            // the pull succeeds.
            if let Ok(mut slot) = observed_fp_out.lock() {
                *slot = Some((host.to_string(), fp.clone()));
            }

            if let Some(ref pinned) = pinned_fp_owned {
                if fingerprint_eq(pinned, &fp) {
                    return Ok(CertificateCheckStatus::CertificateOk);
                }
                return Err(git2::Error::from_str(
                    "SSH host-key mismatch (pinned via GITSYNC_HOST_FINGERPRINT)",
                ));
            }
            if let Some(ref t) = tofu_owned {
                if fingerprint_eq(&t.fingerprint, &fp) {
                    return Ok(CertificateCheckStatus::CertificateOk);
                }
                return Err(git2::Error::from_str(
                    "SSH host-key changed since first pull (TOFU mismatch)",
                ));
            }
            // First pull — accept and let caller store TOFU.
            return Ok(CertificateCheckStatus::CertificateOk);
        }
        // HTTPS / other — defer to libgit2's native verification.
        Ok(CertificateCheckStatus::CertificatePassthrough)
    });

    let mut fetch_opts = FetchOptions::new();
    fetch_opts.remote_callbacks(callbacks);
    fetch_opts.download_tags(AutotagOption::None);

    remote
        .fetch(&[&branch_name], Some(&mut fetch_opts), None)
        .map_err(|e| format!("fetch: {e}"))?;

    // Resolve the upstream target after the fetch and attempt a
    // fast-forward. `FETCH_HEAD` holds what we just pulled.
    let fetch_head = repo
        .find_reference("FETCH_HEAD")
        .map_err(|e| format!("FETCH_HEAD: {e}"))?;
    let fetch_commit = repo
        .reference_to_annotated_commit(&fetch_head)
        .map_err(|e| format!("annotated commit: {e}"))?;

    let (analysis, _) = repo
        .merge_analysis(&[&fetch_commit])
        .map_err(|e| format!("merge analysis: {e}"))?;

    if analysis.is_up_to_date() {
        return Ok((old_sha.clone(), old_sha));
    }
    if !analysis.is_fast_forward() {
        return Err("upstream diverged — fast-forward not possible".into());
    }

    // Fast-forward the current branch reference to the fetched
    // commit, then update the working tree to match. Without the
    // checkout the repo's refs advance but the file on disk still
    // holds the old content — our subsequent reload_config() would
    // see no change.
    let refname = format!("refs/heads/{branch_name}");
    let mut reference = repo
        .find_reference(&refname)
        .map_err(|e| format!("find {refname}: {e}"))?;
    reference
        .set_target(fetch_commit.id(), "fast-forward via /GITSYNC")
        .map_err(|e| format!("set_target: {e}"))?;
    repo.set_head(&refname).map_err(|e| format!("set_head: {e}"))?;
    repo.checkout_head(Some(
        git2::build::CheckoutBuilder::default().force(),
    ))
    .map_err(|e| format!("checkout: {e}"))?;

    Ok((old_sha, fetch_commit.id().to_string()))
}

/// Background task: periodically sync on the configured interval.
/// Stops cleanly when state.shutdown fires. Spawned once at
/// startup if `GIT_CONFIG_PATH` is set.
pub async fn run_loop(state: Arc<ServerState>) {
    let shutdown = Arc::clone(&state.shutdown);
    loop {
        let interval = state.config.load().git_sync_interval();
        let sleep = tokio::time::sleep(std::time::Duration::from_secs(
            if interval == 0 { 3600 } else { interval },
        ));
        tokio::pin!(sleep);
        tokio::select! {
            biased;
            _ = shutdown.notified() => return,
            _ = &mut sleep => {}
        }
        if state.config.load().git_sync_interval() == 0 {
            continue;
        }

        let outcome = sync_once(Arc::clone(&state)).await;
        match &outcome {
            SyncOutcome::Changed { .. } => {
                info!("{}", outcome.summary());
                state.snotice(&outcome.summary()).await;
            }
            SyncOutcome::NoChange { .. } => {
                tracing::debug!("{}", outcome.summary());
            }
            SyncOutcome::Error { .. } => {
                warn!("{}", outcome.summary());
            }
        }
    }
}
