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

/// One pull-and-maybe-reload cycle. git2 is sync; we run the call
/// on a blocking thread via `spawn_blocking` so the async loop
/// doesn't stall. Result comes back as a SyncOutcome ready for
/// operator display.
pub async fn sync_once(state: Arc<ServerState>) -> SyncOutcome {
    let path = match state.config.load().git_config_path() {
        Some(p) => PathBuf::from(p),
        None => {
            return SyncOutcome::Error {
                message: "GIT_CONFIG_PATH not set".into(),
            };
        }
    };

    // Fetch + fast-forward on a blocking thread. The git2 work is
    // synchronous and can block for multiple seconds on a slow
    // remote, so we don't want it on the reactor.
    let sync_state = Arc::clone(&state);
    let result: Result<(String, String), String> =
        tokio::task::spawn_blocking(move || sync_repo(&path)).await.unwrap_or_else(|e| {
            Err(format!("join error: {e}"))
        });

    match result {
        Err(e) => SyncOutcome::Error { message: e },
        Ok((old, new)) if old == new => SyncOutcome::NoChange { head: new },
        Ok((old, new)) => {
            let reload = match sync_state.reload_config() {
                Ok(s) => s,
                Err(e) => format!("reload failed: {e}"),
            };
            SyncOutcome::Changed { old, new, reload }
        }
    }
}

/// Synchronous git2 entry point — open the repo, fetch origin for
/// the current branch, fast-forward-merge. Returns `(old_head,
/// new_head)` shas on success. String errors so we can shuttle the
/// message across the blocking boundary without fighting Send.
fn sync_repo(path: &Path) -> Result<(String, String), String> {
    use git2::{AutotagOption, FetchOptions, RemoteCallbacks, Repository};

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

    // Find the configured upstream for the current branch. Most
    // deploys use `origin/<branch>`; if the branch has no upstream
    // we bail with a clear message rather than guess.
    let upstream_name = {
        let config = repo.config().map_err(|e| format!("config: {e}"))?;
        config
            .get_string(&format!("branch.{branch_name}.remote"))
            .map_err(|_| format!("branch {branch_name} has no upstream remote"))?
    };
    let mut remote = repo
        .find_remote(&upstream_name)
        .map_err(|e| format!("remote {upstream_name}: {e}"))?;

    // Credential resolution: try SSH agent first, then anonymous.
    // Matches libgit2's default-credentials dance.
    let mut callbacks = RemoteCallbacks::new();
    callbacks.credentials(|_url, username_from_url, allowed_types| {
        if allowed_types.is_ssh_key() {
            if let Some(user) = username_from_url {
                return git2::Cred::ssh_key_from_agent(user);
            }
        }
        git2::Cred::default()
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
