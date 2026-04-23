//! Z-lines — IP-based network bans.
//!
//! Like G-lines but the mask is an IP (or IP glob) and matching
//! happens on the client's peer address rather than user@host.
//! Enforcement is at connect: matched clients are refused before
//! they're introduced to the network.
//!
//! Mirrors nefarious2 zline.c + m_zline.c wire semantics.

use std::net::IpAddr;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Zline {
    pub mask: String,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub set_by: String,
    pub set_at: DateTime<Utc>,
    pub lastmod: u64,
    pub lifetime: Option<u64>,
    pub active: bool,
}

impl Zline {
    /// Check whether this Z-line's mask matches a client IP.
    /// Delegates to the shared `ip_mask_matches` helper so the
    /// same CIDR/numeric/glob rules apply here as in GLINE's host
    /// side.
    pub fn matches(&self, ip: IpAddr) -> bool {
        crate::gline::ip_mask_matches(&self.mask, ip)
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

pub type ZlineStore = DashMap<String, Arc<RwLock<Zline>>>;

pub fn mask_key(mask: &str) -> String {
    mask.to_ascii_lowercase()
}
