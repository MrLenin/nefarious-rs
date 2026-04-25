//! SASL relay bridge to a configured services server.
//!
//! When `FEAT_SASL_SERVER` is set and the named services peer is
//! reachable over S2S, client `AUTHENTICATE` exchanges are forwarded
//! to services using the P10 `SASL` token rather than handled
//! locally. The ircd is a transparent relay:
//!
//! - Each client `AUTHENTICATE <b64>` line becomes its own
//!   `<us> SASL <target> <session_token> C :<b64>` S2S line.
//!   **No reassembly on our side** — services reassembles chunked
//!   payloads on its end, so a relayed client can push payloads
//!   arbitrarily larger than our local 32 KiB buffer cap.
//! - `AUTHENTICATE *` → `<us> SASL <target> <session_token> D A`.
//! - Services replies carry the same `<session_token>`; we look up
//!   the originating client and emit the corresponding client-side
//!   numerics or `AUTHENTICATE <challenge>`.
//!
//! ## Session token format
//!
//! `<our_server_numeric>!<local>.<cookie>` — matches nefarious2's
//! `%C!%u.%u` shape. `<local>` is a process-wide monotonic counter
//! so two sessions never collide even if a prior one just ended;
//! `<cookie>` is a 31-bit pseudo-random value that prevents a stale
//! reply from being routed to a new client that happens to occupy
//! the same slot. Cookie randomness comes from a time-mixed counter
//! because cryptographic strength isn't required — services only
//! accepts replies on tokens it handed out, so a guess is not a
//! practical attack vector.
//!
//! ## Timeout
//!
//! A session older than `FEAT_SASL_TIMEOUT` seconds (default 30)
//! is swept by a background task: we emit `D A` to services so its
//! state drops, then send `ERR_SASLFAIL` to the client and clear
//! local SASL flags. Matches nefarious2 m_authenticate.c:318-320.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use p10_proto::ServerNumeric;
use tracing::{debug, info, warn};

use crate::client::ClientId;
use crate::state::ServerState;

/// One in-flight SASL relay session.
///
/// Holds the `Arc<RwLock<Client>>` directly so inbound replies
/// can reach the client even during CAP-phase SASL, when the
/// client hasn't been registered into `ServerState.clients` yet.
/// Services typically SASL-s clients before they send USER/NICK,
/// so pre-registration is the common path.
#[derive(Clone)]
pub struct SaslSession {
    pub client_id: ClientId,
    pub client: Arc<tokio::sync::RwLock<crate::client::Client>>,
    pub started_at: Instant,
    pub mechanism: String,
    /// Account name stashed from an `L` reply so `D S` can finalise
    /// the login. Services sends `L` before `D S` — we apply the
    /// login when `D S` confirms success, not earlier, so a failed
    /// handshake after an accepted `L` doesn't leave a half-logged
    /// client.
    pub pending_account: Option<String>,
}

/// Process-wide SASL relay state. Attached to `ServerState`.
#[derive(Default)]
pub struct SaslState {
    /// Active sessions keyed by our outbound session token.
    sessions: DashMap<String, SaslSession>,
    /// Monotonic counter feeding the session-token `<local>` slot.
    /// Starts at 1 to reserve 0 for "no session".
    counter: AtomicU32,
    /// Mechanisms services announced via `SASL * * M :<csv>`.
    /// Merged with our local list for CAP LS output. Empty until
    /// services broadcasts its mechanism list post-link.
    mechanisms: ArcSwap<Vec<String>>,
}

impl SaslState {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
            counter: AtomicU32::new(1),
            mechanisms: ArcSwap::from_pointee(Vec::new()),
        }
    }

    /// Mint a fresh session token for the local client with numeric
    /// `server_numeric`. The shape mirrors nefarious2's %C!%u.%u
    /// form; the local part is a counter so two tokens from the
    /// same millisecond still differ.
    pub fn new_token<N: std::fmt::Display>(&self, server_numeric: N) -> String {
        let local = self.counter.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0);
        // Mix counter + subsecond nanos into a 31-bit cookie. The
        // cookie's job is only to disambiguate stale replies from
        // fresh ones — not to resist guessing — so this is enough.
        let cookie = (local.wrapping_mul(0x9E37_79B1) ^ nanos) & 0x7FFF_FFFF;
        format!("{server_numeric}!{local}.{cookie}")
    }

    pub fn register(
        &self,
        token: String,
        client_id: ClientId,
        client: Arc<tokio::sync::RwLock<crate::client::Client>>,
        mechanism: String,
    ) {
        self.sessions.insert(
            token,
            SaslSession {
                client_id,
                client,
                started_at: Instant::now(),
                mechanism,
                pending_account: None,
            },
        );
    }

    pub fn lookup(&self, token: &str) -> Option<SaslSession> {
        self.sessions.get(token).map(|e| e.value().clone())
    }

    /// Set the pending account on the session (from an `L` reply).
    /// No-op if the session no longer exists (timeout race).
    pub fn stash_account(&self, token: &str, account: String) {
        if let Some(mut entry) = self.sessions.get_mut(token) {
            entry.pending_account = Some(account);
        }
    }

    pub fn remove(&self, token: &str) -> Option<SaslSession> {
        self.sessions.remove(token).map(|(_, s)| s)
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Update the services-announced mechanism list.
    pub fn set_mechanisms(&self, mechs: Vec<String>) {
        self.mechanisms.store(Arc::new(mechs));
    }

    /// Snapshot the current services-announced mechanism list.
    pub fn mechanisms_snapshot(&self) -> Arc<Vec<String>> {
        self.mechanisms.load_full()
    }

    /// Remove and return every session older than `max_age`.
    pub fn sweep_expired(&self, max_age: Duration) -> Vec<(String, SaslSession)> {
        let now = Instant::now();
        // Snapshot expired keys first so the iteration's shard
        // locks don't contend with the removal's shard locks.
        let expired: Vec<String> = self
            .sessions
            .iter()
            .filter(|e| now.duration_since(e.value().started_at) > max_age)
            .map(|e| e.key().clone())
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for t in expired {
            if let Some((k, s)) = self.sessions.remove(&t) {
                out.push((k, s));
            }
        }
        out
    }
}

/// Spawn the SASL timeout sweeper. Runs every 10s and aborts any
/// session that has been in-flight longer than the configured
/// `SASL_TIMEOUT`. Tied to `state.shutdown` so /DIE exits cleanly.
pub fn spawn_timeout_sweeper(
    state: Arc<ServerState>,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => {
                    let timeout = Duration::from_secs(state.config().sasl_timeout());
                    let expired = state.sasl.sweep_expired(timeout);
                    for (token, session) in expired {
                        handle_timeout(&state, &token, &session).await;
                    }
                }
                _ = shutdown.notified() => break,
            }
        }
    })
}

async fn handle_timeout(state: &ServerState, token: &str, session: &SaslSession) {
    debug!(
        "SASL timeout on session {token} for client {:?}",
        session.client_id
    );
    // Notify services so their session drops too.
    abort_to_services(state, token).await;
    // Use the Arc stored on the session directly — pre-registration
    // clients aren't in state.clients yet.
    let client_arc = &session.client;
    let nick = {
        let c = client_arc.read().await;
        c.nick.clone()
    };
    {
        let c = client_arc.read().await;
        c.send_numeric(
            &state.server_name,
            crate::numeric::ERR_SASLFAIL,
            vec!["SASL authentication timed out".into()],
        );
    }
    info!("SASL session for {nick} timed out after {token}");
    client_arc.write().await.finish_sasl();
}

/// Find the live S2S link we'd use to reach the configured
/// SASL_SERVER, plus the target server's P10 numeric for the
/// wire. Returns `None` when SASL_SERVER is unset, no link is
/// active, or the target server isn't currently in the network —
/// the caller then falls back to local SASL.
///
/// The target on the wire **must** be the server's 2-character
/// base64 numeric, not its hostname — `m_authenticate.c:283` in
/// nefarious2 emits `"%C %C!%u.%u ..."` where both `%C` are
/// server numerics. Sending the name works by accident on
/// name-lookup-capable hubs but isn't the canonical format.
///
/// Reachability check walks `state.remote_servers` by name; a
/// target that isn't there (either never joined, or was SQUIT'd)
/// would otherwise produce a 402 ping-pong 38 seconds later when
/// the session times out. Early return saves the wait and gives
/// the client a clean failure. The racy "target goes down
/// between our check and our send" case still exists; we catch
/// that via the timeout sweeper and via inbound numeric 402.
pub async fn services_link(
    state: &ServerState,
) -> Option<(Arc<crate::s2s::types::ServerLink>, ServerNumeric)> {
    let target_name = state.config().sasl_server()?.to_string();
    let link = state.get_link()?;
    let target_numeric = resolve_server_numeric(state, &target_name).await?;
    Some((link, target_numeric))
}

/// Look up a server by name (case-insensitive) and return its
/// P10 numeric. `None` means we haven't seen that name in burst
/// or since — i.e. it's not currently in the network.
async fn resolve_server_numeric(state: &ServerState, name: &str) -> Option<ServerNumeric> {
    if name.eq_ignore_ascii_case(&state.server_name) {
        // Routing SASL to ourselves is nonsense; caller falls back.
        return None;
    }
    for entry in state.remote_servers.iter() {
        let rs_name = entry.value().read().await.name.clone();
        if rs_name.eq_ignore_ascii_case(name) {
            return Some(*entry.key());
        }
    }
    None
}

/// Abort every in-flight session whose target is no longer in the
/// network. Called when the hub tells us (via numeric 402) that
/// it couldn't route something — a cheap generic fast-fail that
/// doesn't require the numeric to carry a session token.
pub async fn abort_unreachable_sessions(state: &ServerState) {
    let target = match state.config().sasl_server() {
        Some(s) => s.to_string(),
        None => return,
    };
    if resolve_server_numeric(state, &target).await.is_some() {
        return;
    }
    // Target has disappeared. Fail every session — `sweep_expired(0)`
    // drains the whole map (every session is "older than zero
    // seconds"), and `handle_timeout` runs the standard terminal
    // path on each.
    let sessions = state.sasl.sweep_expired(Duration::from_secs(0));
    for (token, session) in sessions {
        handle_timeout(state, &token, &session).await;
    }
}

/// Emit the initial `SASL ... S <mech> [:<initial>]` line to the
/// configured services peer and register the session. The session
/// holds the client Arc so replies can reach the client even
/// during CAP negotiation, when the client isn't yet in
/// `state.clients`.
pub async fn start_relay(
    state: &ServerState,
    client_id: ClientId,
    client: Arc<tokio::sync::RwLock<crate::client::Client>>,
    mechanism: &str,
) -> Option<String> {
    let (link, target) = services_link(state).await?;
    let token = state.sasl.new_token(state.numeric);
    state
        .sasl
        .register(token.clone(), client_id, client, mechanism.to_string());
    // `S` with no initial response — services will reply with a `C`
    // challenge (typically an empty one for PLAIN/EXTERNAL, prompting
    // the client-initial-response).
    let line = format!(
        "{us} SASL {target} {token} S {mech}",
        us = state.numeric,
        mech = mechanism,
    );
    link.send_line(line).await;
    debug!("SASL relay started: {token} mech={mechanism} target={target}");
    Some(token)
}

/// Forward a client AUTHENTICATE chunk to services as `SASL ... C`.
/// `data` is passed through untouched — services reassembles.
pub async fn forward_chunk(state: &ServerState, token: &str, data: &str) {
    let Some((link, target)) = services_link(state).await else {
        warn!("SASL forward_chunk: no services link; dropping");
        return;
    };
    let line = format!(
        "{us} SASL {target} {token} C :{data}",
        us = state.numeric,
    );
    link.send_line(line).await;
}

/// Forward a client `AUTHENTICATE *` as `SASL ... D A`.
pub async fn abort_to_services(state: &ServerState, token: &str) {
    let Some((link, target)) = services_link(state).await else {
        return;
    };
    let line = format!(
        "{us} SASL {target} {token} D A",
        us = state.numeric,
    );
    link.send_line(line).await;
}
