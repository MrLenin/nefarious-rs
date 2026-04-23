use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tokio::sync::{Notify, mpsc};

use irc_proto::{Command, Message};

use crate::capabilities::Capability;


/// A single entry in a client's SILENCE list.
///
/// Stored in the order the user added them; match order doesn't matter
/// because exceptions always win regardless of position. Masks are
/// nick!user@host globs (`*` and `?` wildcards), rfc1459-casefolded at
/// match time — the stored form is whatever the user typed so /SILENCE
/// echoes back cleanly.
#[derive(Debug, Clone)]
pub struct SilenceEntry {
    pub mask: String,
    pub exception: bool,
}

/// Unique client identifier (monotonically increasing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub u64);

static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

impl ClientId {
    pub fn next() -> Self {
        Self(NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed))
    }
}

/// A connected IRC client.
pub struct Client {
    pub id: ClientId,
    /// Current nickname.
    pub nick: String,
    /// PASS value presented during registration, if any. Checked
    /// against the matching Client config block's password at the
    /// end of registration. Cleared after verification so it
    /// doesn't linger in memory.
    pub pass: Option<String>,
    /// Username (from USER command).
    pub user: String,
    /// Realname (from USER command).
    pub realname: String,
    /// Hostname (resolved or IP).
    pub host: String,
    /// Original resolved host, captured once at connect. Used by
    /// /SETHOST undo to revert the `host` field to the pre-cloak
    /// value, and by oper-vision paths that want to see where a
    /// client actually came from. Stays constant across the
    /// connection's lifetime.
    pub real_host: String,
    /// DNSBL mark — set to the listing reason when a DnsBL zone
    /// with action=Mark matched this client's IP at connect. Empty
    /// means unmarked. Opers see this in /WHOIS and /CHECK output;
    /// plain users never see it.
    pub dnsbl_mark: Option<String>,
    /// IP address.
    pub addr: SocketAddr,
    /// Whether the client is using TLS. Consumed later by SASL EXTERNAL
    /// cert-auth and /WHOIS "is using a secure connection" output.
    #[allow(dead_code)]
    pub tls: bool,
    /// User modes (simplified as a set of chars).
    pub modes: HashSet<char>,
    /// Away message, when the user has issued `AWAY :<msg>`. `None` when
    /// the user is present; when `Some`, other users PRIVMSG/NOTICE to this
    /// nick trigger an RPL_AWAY response.
    pub away_message: Option<String>,
    /// Logged-in account name. Populated by SASL in Phase 3; used here
    /// to fill the `@account` tag for `account-tag`-enabled recipients
    /// and the extended-join payload in Phase 2.7.
    pub account: Option<String>,
    /// Oper privileges granted on successful /OPER. Populated from the
    /// matching Operator config block; names match nefarious2's
    /// `privtab` (e.g. "KILL", "REHASH", "OPMODE"). Empty for non-opers.
    /// Propagated over S2S via the `PRIVS` token so peers know what
    /// remote opers are allowed to do.
    pub privs: HashSet<String>,
    /// IRCv3 MONITOR watch list — casefolded nicks this client wants
    /// 730/731 notifications about. Cross-indexed on ServerState via
    /// `monitored_by` so state-change broadcasts can find watchers
    /// without scanning every client.
    pub monitored: HashSet<String>,
    /// Dalnet/Unreal WATCH list — casefolded nicks this client wants
    /// 604/605/602 notifications about. Cross-indexed on ServerState
    /// via `watched_by`. Same lifecycle hooks fire for both — clients
    /// get MONITOR numerics for nicks in `monitored` and WATCH
    /// numerics for nicks in `watched`, and can use both at once.
    pub watched: HashSet<String>,
    /// SILENCE entries — masks whose senders are filtered before
    /// delivery. An entry with `exception = true` is a positive-match
    /// override: messages matching an exception pass through even if
    /// a non-exception entry would otherwise silence them. Matches
    /// nefarious2 cli_user(sptr)->silence ordering (exceptions win).
    pub silence: Vec<SilenceEntry>,
    /// Channels this client is in.
    pub channels: HashSet<String>,
    /// Connection timestamp.
    pub connected_at: chrono::DateTime<chrono::Utc>,
    /// Last activity timestamp.
    pub last_active: chrono::DateTime<chrono::Utc>,
    /// Timestamp of the current nickname as epoch seconds. Used as the
    /// tiebreaker for P10 nick-TS collision resolution: the side holding
    /// the nick with the older nick_ts wins. Updated on every successful
    /// NICK change (including the initial one during registration).
    pub nick_ts: u64,
    /// Channel for sending messages to this client.
    pub sender: mpsc::Sender<Message>,
    /// Port the client connected on. Carried for future /WHOIS and
    /// IAuth decisions that dispatch on listener.
    #[allow(dead_code)]
    pub listener_port: u16,
    /// Notified when the server needs this client's message loop to exit
    /// (e.g. after losing a P10 nick-TS collision). The loop uses this as
    /// a `tokio::select!` cancellation branch so cleanup still runs.
    pub disconnect_signal: Arc<Notify>,
    /// Short reason passed to the QUIT broadcast when we initiate the
    /// disconnect via `disconnect_signal`.
    pub disconnect_reason: std::sync::Mutex<Option<String>>,

    // --- IRCv3 CAP negotiation state ---
    /// Set while CAP negotiation is in progress. Registration is blocked
    /// from completing until the client either sends CAP END or never
    /// starts negotiation at all.
    pub cap_negotiating: bool,
    /// CAP version the client announced in `CAP LS <version>`. 0 means
    /// pre-IRCv3 (no LS ever sent) or v1 (no number after `LS`).
    pub cap_version: u16,
    /// The capabilities this client has successfully REQ'd and we ACK'd.
    pub enabled_caps: HashSet<Capability>,
    /// Monotonic counter for BATCH ids allocated to this client. Each
    /// labeled-response or other server-originated batch gets a fresh
    /// id. Clients only see their own ids, so per-client suffices.
    pub batch_counter: AtomicU32,
    /// SASL mechanism currently in progress, if any. Set by the first
    /// `AUTHENTICATE <mech>` line; cleared on success, failure, or
    /// explicit abort (`AUTHENTICATE *`). While `Some`, the next
    /// `AUTHENTICATE <payload>` line is interpreted as the mechanism's
    /// initial client response.
    pub sasl_mechanism: Option<String>,
    /// Subject common name extracted from the peer's TLS client
    /// certificate at handshake time. Populated only when the client
    /// presented a cert and it parsed as UTF-8. Used by SASL EXTERNAL
    /// (Phase 3.3) to map the certificate to an account without
    /// requiring a password.
    pub tls_cert_cn: Option<String>,
}

/// Per-dispatch labeled-response capture.
///
/// Lives in a `tokio::task_local!` set by the dispatcher for the
/// duration of handling a labeled command, rather than on the
/// `Client` struct. This scopes capture to the dispatching task —
/// sends from any other task (S2S reader, another client's
/// dispatcher, keepalive timers) targeting the same client bypass
/// the buffer and go straight to the outbound queue, which is the
/// correct behaviour: those aren't replies to the labeled command.
///
/// `originator_id` lets `Client::send` cheaply filter out sends the
/// dispatching task makes to *other* clients (e.g. channel fan-out
/// broadcasts). Only sends to the originator are buffered.
pub struct LabelCapture {
    pub originator_id: ClientId,
    pub label: String,
    pub replies: Vec<Message>,
}

tokio::task_local! {
    /// Active label capture for the current dispatch task, if any.
    /// `Mutex` because `Client::send` takes `&self` and the value
    /// needs interior mutability; contention is essentially nil
    /// since only the dispatching task accesses its own task-local.
    pub static LABEL_CAPTURE: std::sync::Mutex<LabelCapture>;
}

impl Client {
    pub fn new(
        addr: SocketAddr,
        tls: bool,
        listener_port: u16,
        sender: mpsc::Sender<Message>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: ClientId::next(),
            nick: String::new(),
            pass: None,
            user: String::new(),
            realname: String::new(),
            host: addr.ip().to_string(),
            real_host: addr.ip().to_string(),
            dnsbl_mark: None,
            addr,
            tls,
            modes: HashSet::new(),
            away_message: None,
            account: None,
            privs: HashSet::new(),
            monitored: HashSet::new(),
            watched: HashSet::new(),
            silence: Vec::new(),
            channels: HashSet::new(),
            connected_at: now,
            last_active: now,
            nick_ts: now.timestamp() as u64,
            sender,
            listener_port,
            disconnect_signal: Arc::new(Notify::new()),
            disconnect_reason: std::sync::Mutex::new(None),
            cap_negotiating: false,
            cap_version: 0,
            enabled_caps: HashSet::new(),
            batch_counter: AtomicU32::new(1),
            sasl_mechanism: None,
            tls_cert_cn: None,
        }
    }

    /// Return the host string to render for this client when the
    /// audience isn't themselves or an oper. Mirrors the C hiding
    /// chain in nefarious2 s_user.c `hide_hostmask`. The style knob
    /// is FEAT_HOST_HIDING_STYLE:
    ///
    /// - Style 0  → never cloak (host as-is)
    /// - Style 1  → `<account>.<suffix>` when logged in with a
    ///              `hidden_host_suffix`; otherwise real host.
    /// - Style 2  → crypto cloak (hidehost_ipv4 / _ipv6 for IP
    ///              hosts; hidehost_normalhost for resolved names).
    /// - Style 3  → style 1 when logged in, style 2 otherwise.
    ///
    /// Callers that want the real host unconditionally (self-WHOIS,
    /// oper-vision, IAuth logs) should read `self.host` directly.
    pub fn visible_host(&self, config: &irc_config::Config) -> String {
        if !self.modes.contains(&'x') {
            return self.host.clone();
        }

        let style = config.host_hiding_style();
        let is_account = self.account.is_some();

        // Account-based cloak path.
        let account_cloak = || -> Option<String> {
            if let (Some(account), Some(suffix)) = (
                self.account.as_ref(),
                config.general.hidden_host_suffix.as_ref(),
            ) {
                Some(format!("{account}.{suffix}"))
            } else {
                None
            }
        };

        // Crypto cloak path.
        let crypto_cloak = || -> Option<String> {
            let keys = config.host_hiding_keys();
            let prefix = config.host_hiding_prefix();
            let components = config.host_hiding_components() as usize;

            // If the host looks like a numeric IP, cloak by IP.
            // Otherwise cloak the hostname.
            match self.host.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(v4)) => {
                    Some(crate::cloaking::hidehost_ipv4(v4.octets(), keys))
                }
                Ok(std::net::IpAddr::V6(v6)) => {
                    Some(crate::cloaking::hidehost_ipv6(v6.segments(), keys))
                }
                Err(_) => Some(crate::cloaking::hidehost_normalhost(
                    &self.host,
                    components.max(1),
                    keys,
                    prefix,
                )),
            }
        };

        match style {
            0 => self.host.clone(),
            1 => account_cloak().unwrap_or_else(|| self.host.clone()),
            2 => crypto_cloak().unwrap_or_else(|| self.host.clone()),
            3 => {
                if is_account {
                    account_cloak()
                        .or_else(crypto_cloak)
                        .unwrap_or_else(|| self.host.clone())
                } else {
                    crypto_cloak().unwrap_or_else(|| self.host.clone())
                }
            }
            _ => self.host.clone(),
        }
    }

    /// Send a message to this client, bypassing the labeled-response
    /// capture. Used by the flush code itself and by tasks that
    /// explicitly want to avoid buffering. Normal sends should go
    /// through `send()`.
    pub fn send_raw(&self, msg: Message) {
        use tokio::sync::mpsc::error::TrySendError;
        if let Err(TrySendError::Full(_)) = self.sender.try_send(msg) {
            self.request_disconnect("SendQ exceeded");
        }
    }

    /// Whether the given capability is active for this client.
    pub fn has_cap(&self, cap: Capability) -> bool {
        self.enabled_caps.contains(&cap)
    }

    /// Whether `sender_prefix` (nick!user@host form) is filtered by
    /// this client's SILENCE list. Exceptions (`~mask`) override
    /// matching silence masks — if any exception matches, the sender
    /// is allowed through regardless of other entries. Used by the
    /// private PRIVMSG/NOTICE path both locally and when dispatching
    /// inbound S2S messages that target a local user.
    pub fn is_silenced(&self, sender_prefix: &str) -> bool {
        if self.silence.is_empty() {
            return false;
        }
        let mut silenced = false;
        for entry in &self.silence {
            if crate::channel::wildcard_match(&entry.mask, sender_prefix) {
                if entry.exception {
                    return false;
                }
                silenced = true;
            }
        }
        silenced
    }

    /// Allocate a unique BATCH id string for this client. Short base36
    /// to keep the wire line size down; monotonic so replays are easy to
    /// read in packet captures.
    pub fn next_batch_id(&self) -> String {
        let n = self.batch_counter.fetch_add(1, Ordering::Relaxed);
        // base36-ish using digits+letters; plenty of headroom with u32.
        format!("b{n:x}")
    }

    /// Request that the connection task disconnect this client and run
    /// normal cleanup. Used for P10-initiated kicks (nick-TS collision,
    /// KILL, etc.) where we need to terminate the socket ourselves.
    pub fn request_disconnect(&self, reason: impl Into<String>) {
        if let Ok(mut slot) = self.disconnect_reason.lock() {
            if slot.is_none() {
                *slot = Some(reason.into());
            }
        }
        self.disconnect_signal.notify_one();
    }

    /// Full prefix in nick!user@host format.
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }

    /// Whether the client has completed registration (has nick + user).
    pub fn is_registered(&self) -> bool {
        !self.nick.is_empty() && !self.user.is_empty()
    }

    /// Send a message to this client (non-blocking).
    ///
    /// If the current task has an active labeled-response capture
    /// AND this client is the originator of the labeled command,
    /// the message is captured for later flush. All other paths
    /// (unrelated broadcasts from the S2S reader, other clients'
    /// dispatchers, keepalive timers — none of which are in the
    /// dispatching task) bypass the buffer and go straight to the
    /// outbound queue. If the queue is full the client is
    /// disconnected with "SendQ exceeded" — dropping messages
    /// silently would cause state drift with the rest of the
    /// network.
    pub fn send(&self, msg: Message) {
        if self.try_buffer_for_label(&msg) {
            return;
        }
        self.send_raw(msg);
    }

    /// Push `msg` into the active labeled-response capture if we are
    /// inside the dispatching task AND this client is the originator
    /// of the labeled command. Returns true when captured.
    fn try_buffer_for_label(&self, msg: &Message) -> bool {
        LABEL_CAPTURE
            .try_with(|cell| {
                let mut guard = cell.lock().expect("label capture mutex poisoned");
                if guard.originator_id != self.id {
                    return false;
                }
                guard.replies.push(msg.clone());
                true
            })
            .unwrap_or(false)
    }

    /// Send a user-originated event (PRIVMSG, NOTICE, JOIN, PART, …)
    /// with IRCv3 tags applied for this recipient's enabled caps.
    /// `src` carries the event metadata (time, source account) the
    /// tags need; broadcast call sites build one `SourceInfo` per
    /// event and reuse it across every recipient.
    pub fn send_from(&self, msg: Message, src: &crate::tags::SourceInfo) {
        self.send(crate::tags::tagged_for(msg, self, src));
    }

    /// Send a numeric reply from the server.
    pub fn send_numeric(&self, server_name: &str, numeric: u16, params: Vec<String>) {
        let mut full_params = vec![self.nick.clone()];
        full_params.extend(params);
        self.send(Message::with_source(
            server_name,
            Command::Numeric(numeric),
            full_params,
        ));
    }

}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("id", &self.id)
            .field("nick", &self.nick)
            .field("user", &self.user)
            .field("host", &self.host)
            .finish()
    }
}
