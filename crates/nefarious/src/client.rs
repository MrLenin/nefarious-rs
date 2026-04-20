use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::mpsc;

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
    /// Channel for sending messages to this client.
    pub sender: mpsc::Sender<Message>,
    /// Port the client connected on.
    pub listener_port: u16,
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
            sender,
            listener_port,
        }
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
