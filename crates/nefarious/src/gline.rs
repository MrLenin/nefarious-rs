//! Global network bans (G-lines).
//!
//! A G-line is a network-wide client ban applied on connect. Each
//! entry targets a `user@host` mask (globbed) with optional IP
//! CIDR handling; clients matching an active G-line are disconnected
//! with the stored reason. Inactive G-lines are retained so that
//! later activation replays cleanly without re-adding.
//!
//! Storage and wire semantics follow nefarious2 gline.c + m_gline.c.
//! We start with the 90% case: activate/deactivate via inbound GL
//! token, broadcast to peers, and enforcement on local connect +
//! post-add scan. Lifetime/modify/real-name/version GLines come
//! next once the base path is exercised against a live peer.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::sync::RwLock;

#[derive(Debug, Clone)]
pub struct Gline {
    /// `user@host` glob. We don't pre-split so debug logs show the
    /// exact mask the operator set.
    pub mask: String,
    /// Free-form reason shown to the disconnected client. Matches
    /// `gline->gl_reason` in C.
    pub reason: String,
    /// Absolute expiry time; `None` means "no expiry scheduled"
    /// (caller must treat it as permanent for matching purposes).
    pub expires_at: Option<DateTime<Utc>>,
    /// Who set the gline — an oper nick, server name, or `*` for
    /// services. Stored verbatim for display.
    pub set_by: String,
    /// When we first learned of this gline. Equal to the wire
    /// `lastmod` in C, recorded as a UTC timestamp for easy
    /// comparison against now().
    pub set_at: DateTime<Utc>,
    /// Last-modification timestamp in epoch seconds. Peers use this
    /// as a Lamport clock to decide which of two conflicting updates
    /// wins; we preserve it across relays without modification.
    pub lastmod: u64,
    /// Optional expiry grace period after the mask technically
    /// expires but should still be propagated for sync purposes.
    /// Preserved but unused in enforcement yet.
    pub lifetime: Option<u64>,
    /// Whether the gline is currently enforcing (active). Peers can
    /// deactivate without removing so later reactivation preserves
    /// history; `Gline` instances with `active = false` stay in the
    /// store until they expire.
    pub active: bool,
}

impl Gline {
    /// Whether this gline applies to the given `user@host` string.
    /// Simple glob match only (no CIDR) for now — matches the mask
    /// stored at construction time via the shared channel.rs helper.
    pub fn matches(&self, user_host: &str) -> bool {
        crate::channel::wildcard_match(&self.mask, user_host)
    }

    /// Whether this gline should be enforced right now. Expired or
    /// inactive glines report false without removing themselves;
    /// cleanup happens via a sweep, not a match check.
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

/// Casefolded-mask → Gline map. Concurrent access is fine with
/// DashMap; write paths (GL add/remove) are infrequent enough that
/// the internal shard locking doesn't contend.
pub type GlineStore = DashMap<String, Arc<RwLock<Gline>>>;

/// Normalise a mask for storage — lower-case so lookups don't miss
/// due to case variation across peers. The mask stored on the Gline
/// itself keeps its original case for display.
pub fn mask_key(mask: &str) -> String {
    mask.to_ascii_lowercase()
}
