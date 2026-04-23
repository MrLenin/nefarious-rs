//! Jupes — network-wide server-name lockouts.
//!
//! A jupe is a ban on a server name: the named server can't link
//! into the network while the jupe is active, which prevents nick
//! or channel hijacks via a rogue server introducing itself.
//!
//! Lighter than G/S/Z-lines on the wire: no lifetime field, no
//! user@host / IP split, just the server name and a reason.
//! Mirrors nefarious2 jupe.c + m_jupe.c.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Jupe {
    /// Server name being juped. Case-insensitive match; stored as
    /// the operator typed it for display.
    pub server: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub set_by: String,
    pub set_at: DateTime<Utc>,
    pub lastmod: u64,
    pub active: bool,
}

impl Jupe {
    pub fn matches(&self, server_name: &str) -> bool {
        self.server.eq_ignore_ascii_case(server_name)
    }

    pub fn is_enforceable(&self, now: DateTime<Utc>) -> bool {
        if !self.active {
            return false;
        }
        match self.expires_at {
            Some(exp) => exp > now,
            None => true,
        }
    }
}

pub type JupeStore = DashMap<String, Arc<RwLock<Jupe>>>;

pub fn name_key(server: &str) -> String {
    server.to_ascii_lowercase()
}
