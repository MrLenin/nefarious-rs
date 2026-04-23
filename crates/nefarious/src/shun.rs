//! Shuns — silencing network bans.
//!
//! A shun is a network-wide gag: the matched user stays connected
//! but can't send to channels or deliver private messages.
//! Structurally identical to G-lines (mask, reason, lifetime,
//! lastmod, active flag) — the difference is only in enforcement,
//! which happens at the outbound messaging path rather than at
//! connect.
//!
//! Mirrors nefarious2 shun.c + m_shun.c. We ship the same wire and
//! storage surface as G-lines so a mixed network stays in sync.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Shun {
    pub mask: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub set_by: String,
    pub set_at: DateTime<Utc>,
    pub lastmod: u64,
    pub lifetime: Option<u64>,
    pub active: bool,
}

impl Shun {
    /// Match against a client identity. Shares the gline matcher so
    /// CIDR/glob semantics are identical between the two surfaces.
    pub fn matches(&self, user: &str, host: &str, ip: IpAddr) -> bool {
        crate::gline::user_host_mask_matches(&self.mask, user, host, ip)
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

pub type ShunStore = DashMap<String, Arc<RwLock<Shun>>>;

pub fn mask_key(mask: &str) -> String {
    mask.to_ascii_lowercase()
}
