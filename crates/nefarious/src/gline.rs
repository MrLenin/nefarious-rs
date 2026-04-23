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

use std::net::IpAddr;
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
    /// Whether this gline applies to the given client identity.
    /// Handles three match shapes in priority order:
    ///
    /// 1. `user@cidr` — host side parses as an IPv4/IPv6 CIDR
    ///    (`192.168.0.0/24` or `2001:db8::/32`). User side is
    ///    glob-matched against `user`.
    /// 2. `user@host` with the host being a bare IP — numeric
    ///    equality against `ip`.
    /// 3. Plain glob fallback — compare the whole mask to the
    ///    reassembled `user@host` string (covers resolved hosts
    ///    like `*@*.example.com`).
    ///
    /// The combined approach means operators can ban either on
    /// forward-resolved hostname masks (classic) or on network
    /// prefixes (`/24`) without needing separate mask syntax.
    pub fn matches(&self, user: &str, host: &str, ip: IpAddr) -> bool {
        user_host_mask_matches(&self.mask, user, host, ip)
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

/// Parse an interval string like `1d`, `3h30m`, or bare `3600` into
/// seconds. Matches nefarious2 ParseInterval in ircd_string.c:
/// digits before a unit char scale by that unit, trailing digits
/// are seconds. Unknown unit chars contribute zero. Returns 0 on
/// empty input.
pub fn parse_interval(s: &str) -> u64 {
    let mut seconds: u64 = 0;
    let mut partial: u64 = 0;
    for c in s.chars() {
        if let Some(d) = c.to_digit(10) {
            partial = partial.saturating_mul(10).saturating_add(d as u64);
        } else {
            let unit = match c {
                'y' => 365 * 24 * 60 * 60,
                'M' => 31 * 24 * 60 * 60,
                'w' => 7 * 24 * 60 * 60,
                'd' => 24 * 60 * 60,
                'h' => 60 * 60,
                'm' => 60,
                's' => 1,
                _ => 0,
            };
            seconds = seconds.saturating_add(partial.saturating_mul(unit));
            partial = 0;
        }
    }
    seconds.saturating_add(partial)
}

/// Match a `user@host` ban mask against a client identity.
///
/// Shared by GLINE, SHUN, and the K-line checker so the same mask
/// syntax (glob + CIDR) applies network-wide. Splits the mask on
/// `@` and considers the right-hand side as either a CIDR, a
/// numeric IP, or a glob; the left-hand side is always a glob on
/// the user string. When there's no `@` in the mask the whole
/// thing falls through to a single glob against `user@host` —
/// preserves backwards compatibility with naive masks.
pub fn user_host_mask_matches(
    mask: &str,
    user: &str,
    host: &str,
    ip: IpAddr,
) -> bool {
    // Fall-through path: no '@' → glob against full prefix.
    let Some(at) = mask.rfind('@') else {
        let combined = format!("{user}@{host}");
        return crate::channel::wildcard_match(mask, &combined);
    };
    let (user_part, host_part) = (&mask[..at], &mask[at + 1..]);

    // User side is always a glob.
    if !crate::channel::wildcard_match(user_part, user) {
        return false;
    }

    // Host side: try CIDR → numeric IP → glob, in that order.
    if host_part.contains('/') {
        if let Some(matched) = ip_in_cidr(ip, host_part) {
            return matched;
        }
    }
    if let Ok(mask_ip) = host_part.parse::<IpAddr>() {
        return mask_ip == ip;
    }
    // Fall back to glob against the textual host. `wildcard_match`
    // is rfc1459-casefolded, which is right for hostname matches.
    crate::channel::wildcard_match(host_part, host)
}

/// Match a bare IP/CIDR mask against a client IP. Used by ZLINE,
/// which doesn't carry a user part. Glob fallback is still supplied
/// for peers that emit ZLINE masks as hostname patterns rather than
/// numeric CIDR.
pub fn ip_mask_matches(mask: &str, ip: IpAddr) -> bool {
    if mask.contains('/') {
        if let Some(matched) = ip_in_cidr(ip, mask) {
            return matched;
        }
    }
    if let Ok(mask_ip) = mask.parse::<IpAddr>() {
        return mask_ip == ip;
    }
    // Fall back: treat as a glob on the IP's textual form.
    crate::channel::wildcard_match(mask, &ip.to_string())
}

/// Parse `cidr` as an IPv4 or IPv6 prefix and test whether `ip`
/// falls within it. Returns `Some(matched)` on a parseable mask
/// and `None` if `cidr` is malformed — callers then decide what
/// to do (we fall back to glob on malformed masks).
pub fn ip_in_cidr(ip: IpAddr, cidr: &str) -> Option<bool> {
    let (net_str, bits_str) = cidr.split_once('/')?;
    let net: IpAddr = net_str.parse().ok()?;
    let bits: u8 = bits_str.parse().ok()?;
    match (net, ip) {
        (IpAddr::V4(net), IpAddr::V4(ip)) => {
            if bits > 32 {
                return None;
            }
            let net_n = u32::from_be_bytes(net.octets());
            let ip_n = u32::from_be_bytes(ip.octets());
            // 0-bit prefix matches everything; u32 shift by 32 is UB.
            if bits == 0 {
                return Some(true);
            }
            let mask = u32::MAX << (32 - bits);
            Some((net_n & mask) == (ip_n & mask))
        }
        (IpAddr::V6(net), IpAddr::V6(ip)) => {
            if bits > 128 {
                return None;
            }
            let net_n = u128::from_be_bytes(net.octets());
            let ip_n = u128::from_be_bytes(ip.octets());
            if bits == 0 {
                return Some(true);
            }
            let mask = u128::MAX << (128 - bits);
            Some((net_n & mask) == (ip_n & mask))
        }
        // Mixed address families never match. This is what C does
        // too — a 4-octet mask against a v6 client is simply "no".
        _ => Some(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn interval_bare_seconds() {
        assert_eq!(parse_interval("3600"), 3600);
    }

    #[test]
    fn interval_units() {
        assert_eq!(parse_interval("1d"), 86400);
        assert_eq!(parse_interval("1h30m"), 5400);
        assert_eq!(parse_interval("7d"), 604800);
    }

    #[test]
    fn interval_trailing_seconds() {
        // "1m30" → 60 + 30 = 90
        assert_eq!(parse_interval("1m30"), 90);
    }

    #[test]
    fn interval_unknown_unit() {
        // Unknown unit treated as 0 multiplier; digits before it are lost.
        assert_eq!(parse_interval("5q"), 0);
    }

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn cidr_ipv4_prefix() {
        assert_eq!(ip_in_cidr(v4(192, 168, 1, 42), "192.168.0.0/16"), Some(true));
        assert_eq!(ip_in_cidr(v4(10, 0, 0, 1), "192.168.0.0/16"), Some(false));
        assert_eq!(ip_in_cidr(v4(192, 168, 1, 42), "192.168.1.0/24"), Some(true));
        assert_eq!(ip_in_cidr(v4(192, 168, 2, 42), "192.168.1.0/24"), Some(false));
    }

    #[test]
    fn cidr_edges() {
        // /0 matches anything
        assert_eq!(ip_in_cidr(v4(8, 8, 8, 8), "0.0.0.0/0"), Some(true));
        // /32 matches exact
        assert_eq!(ip_in_cidr(v4(1, 2, 3, 4), "1.2.3.4/32"), Some(true));
        assert_eq!(ip_in_cidr(v4(1, 2, 3, 5), "1.2.3.4/32"), Some(false));
    }

    #[test]
    fn cidr_malformed_returns_none() {
        assert_eq!(ip_in_cidr(v4(1, 2, 3, 4), "not-a-cidr"), None);
        assert_eq!(ip_in_cidr(v4(1, 2, 3, 4), "1.2.3.4/99"), None);
    }

    #[test]
    fn user_host_mask_cidr_and_user() {
        // Classic glob-on-host should still work.
        assert!(user_host_mask_matches(
            "*bad*@*.example.com",
            "verybadnick",
            "host.example.com",
            v4(1, 2, 3, 4),
        ));
        // CIDR host side: the host glob is ignored in favour of the
        // numeric compare.
        assert!(user_host_mask_matches(
            "*@192.168.0.0/16",
            "alice",
            "resolved-to-something-else.example",
            v4(192, 168, 1, 1),
        ));
        assert!(!user_host_mask_matches(
            "*@192.168.0.0/16",
            "alice",
            "whatever",
            v4(10, 0, 0, 1),
        ));
        // User glob still gates when host CIDR passes.
        assert!(!user_host_mask_matches(
            "admin@192.168.0.0/16",
            "alice",
            "whatever",
            v4(192, 168, 1, 1),
        ));
    }

    #[test]
    fn ip_mask_bare_ip_and_cidr() {
        assert!(ip_mask_matches("1.2.3.4", v4(1, 2, 3, 4)));
        assert!(!ip_mask_matches("1.2.3.4", v4(1, 2, 3, 5)));
        assert!(ip_mask_matches("192.168.0.0/16", v4(192, 168, 10, 20)));
        // Glob fallback — host-shaped IP glob.
        assert!(ip_mask_matches("192.168.*.*", v4(192, 168, 1, 1)));
    }
}
