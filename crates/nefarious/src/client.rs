use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::{Notify, mpsc};

use irc_proto::{Command, Message};


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
            channels: HashSet::new(),
            connected_at: now,
            last_active: now,
            nick_ts: now.timestamp() as u64,
            sender,
            listener_port,
            disconnect_signal: Arc::new(Notify::new()),
            disconnect_reason: std::sync::Mutex::new(None),
        }
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

    /// Send a message to this client (non-blocking, drops if buffer full).
    pub fn send(&self, msg: Message) {
        let _ = self.sender.try_send(msg);
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
