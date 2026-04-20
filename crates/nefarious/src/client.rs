use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Notify, mpsc};

use irc_proto::{Command, Message};

use crate::capabilities::Capability;


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
    /// Username (from USER command).
    pub user: String,
    /// Realname (from USER command).
    pub realname: String,
    /// Hostname (resolved or IP).
    pub host: String,
    /// IP address.
    pub addr: SocketAddr,
    /// Whether the client is using TLS.
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
    /// Port the client connected on.
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
            user: String::new(),
            realname: String::new(),
            host: addr.ip().to_string(),
            addr,
            tls,
            modes: HashSet::new(),
            away_message: None,
            account: None,
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
        }
    }

    /// Whether the given capability is active for this client.
    pub fn has_cap(&self, cap: Capability) -> bool {
        self.enabled_caps.contains(&cap)
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
    /// If the outbound queue is full the client is disconnected with
    /// "SendQ exceeded" — dropping messages silently would cause state
    /// drift with the rest of the network. `TrySendError::Closed` means
    /// the writer task already exited, so there is nothing more to do.
    pub fn send(&self, msg: Message) {
        use tokio::sync::mpsc::error::TrySendError;
        if let Err(TrySendError::Full(_)) = self.sender.try_send(msg) {
            self.request_disconnect("SendQ exceeded");
        }
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

    /// Send an error numeric with a trailing message.
    pub fn send_error(&self, server_name: &str, numeric: u16, message: &str) {
        self.send_numeric(server_name, numeric, vec![message.to_string()]);
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
