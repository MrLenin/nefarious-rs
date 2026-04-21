use std::collections::HashSet;
use std::sync::Arc;

use tokio::sync::mpsc;

use p10_proto::{ClientNumeric, ServerNumeric};

/// A remote server we know about (from burst or SERVER message).
#[derive(Debug)]
pub struct RemoteServer {
    pub name: String,
    pub numeric: ServerNumeric,
    pub hop_count: u16,
    pub description: String,
    pub uplink: ServerNumeric,
    pub timestamp: u64,
    pub flags: ServerFlags,
}

#[derive(Debug, Default)]
pub struct ServerFlags {
    pub hub: bool,
    pub ipv6: bool,
    pub oplevels: bool,
    pub service: bool,
}

impl ServerFlags {
    pub fn from_flag_str(s: &str) -> Self {
        let mut flags = Self::default();
        for c in s.chars() {
            match c {
                'h' => flags.hub = true,
                '6' => flags.ipv6 = true,
                'o' => flags.oplevels = true,
                's' => flags.service = true,
                '+' => {} // skip prefix
                _ => {}
            }
        }
        flags
    }

    pub fn to_flag_str(&self) -> String {
        let mut s = String::from("+");
        if self.hub {
            s.push('h');
        }
        if self.ipv6 {
            s.push('6');
        }
        if self.oplevels {
            s.push('o');
        }
        if self.service {
            s.push('s');
        }
        s
    }
}

/// A user on a remote server (from burst or NICK message).
#[derive(Debug)]
pub struct RemoteClient {
    pub nick: String,
    pub numeric: ClientNumeric,
    pub server: ServerNumeric,
    pub user: String,
    pub host: String,
    pub realname: String,
    pub ip_base64: String,
    pub modes: HashSet<char>,
    pub account: Option<String>,
    pub nick_ts: u64,
    pub channels: HashSet<String>,
    /// AWAY text set by the remote side. `None` when the user is
    /// present; `Some(msg)` when they have AWAY set. Used for
    /// CAP-gated AWAY emit during channel burst join so clients with
    /// `away-notify` learn the state without a /WHO round-trip.
    pub away_message: Option<String>,
}

impl RemoteClient {
    /// Full prefix in nick!user@host format (for relaying to local clients).
    pub fn prefix(&self) -> String {
        format!("{}!{}@{}", self.nick, self.user, self.host)
    }
}

/// State of a server link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Exchanging PASS/SERVER.
    Handshake,
    /// Receiving/sending burst data.
    Bursting,
    /// Normal operation.
    Active,
}

/// An active server-to-server link.
pub struct ServerLink {
    pub numeric: ServerNumeric,
    pub name: String,
    /// Send raw P10 lines to the remote server.
    pub sender: mpsc::Sender<String>,
    pub state: std::sync::atomic::AtomicU8,
}

impl ServerLink {
    pub fn new(numeric: ServerNumeric, name: String, sender: mpsc::Sender<String>) -> Self {
        Self {
            numeric,
            name,
            sender,
            state: std::sync::atomic::AtomicU8::new(LinkState::Handshake as u8),
        }
    }

    pub fn get_state(&self) -> LinkState {
        match self.state.load(std::sync::atomic::Ordering::Relaxed) {
            0 => LinkState::Handshake,
            1 => LinkState::Bursting,
            _ => LinkState::Active,
        }
    }

    pub fn set_state(&self, state: LinkState) {
        self.state
            .store(state as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// Send a raw P10 line to the remote server.
    pub async fn send_line(&self, line: String) {
        let _ = self.sender.send(line).await;
    }

    /// Send a P10 message to the remote server.
    pub async fn send_msg(&self, msg: &p10_proto::P10Message) {
        self.send_line(msg.to_wire()).await;
    }
}

impl std::fmt::Debug for ServerLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerLink")
            .field("numeric", &self.numeric)
            .field("name", &self.name)
            .field("state", &self.get_state())
            .finish()
    }
}
