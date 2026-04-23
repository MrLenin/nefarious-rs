//! DNSBL (DNS-based blackhole list) checks at connect time.
//!
//! For each configured `DNSBL {}` block we build an RFC 5782 query
//! name — octet-reversed IPv4 like `4.3.2.1.<zone>` or
//! nibble-reversed IPv6 — and resolve it through the same
//! hickory-resolver instance the reverse-DNS path uses. A
//! successful lookup means the IP is listed; the zone's `host`
//! bitmask decides which reply codes count, and the block's action
//! decides whether to disconnect, mark, or whitelist the client.
//!
//! ## Bitmask matching
//!
//! Per nefarious2 dnsbl.c, the conf's `host = "2,3,4,5,6,7,9"` is
//! parsed at config time into a u32 bitmask `(1<<2)|...|(1<<9)`.
//! When a reply like `127.0.0.4` arrives we treat the last octet
//! as an *index* and check `(1u32 << 4) & bitmask`. This is
//! deliberately not a bitwise-AND of the octet itself — the octet
//! is the list category number, and the conf says which categories
//! we care about.
//!
//! ## Multiple blocks per zone
//!
//! The testnet conf defines several `DNSBL` blocks for the same
//! zone (`dnsbl.afternet.org` once with `host="2"` action=whitelist,
//! once with `host="250"` action=block_anon). We treat each block
//! independently and dedupe DNS work by zone name — one query per
//! unique zone, then every block sharing that zone is evaluated
//! against every returned A record.
//!
//! ## Caching
//!
//! Results are cached per IP for `DNSBL_CACHETIME` seconds (default
//! 6h). Repeat connects from the same address (think bouncer
//! reconnect storms) skip the DNS round trip entirely. A
//! background sweeper task evicts expired entries every 5 minutes.
//!
//! Lookups fail open: NXDOMAIN, network errors, and timeouts all
//! resolve to `Clean`. We don't refuse a connection on DNS
//! ambiguity.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hickory_resolver::TokioResolver;
use tracing::{debug, warn};

use irc_config::{DnsBlAction, DnsBlConfig};

/// Build the RFC 5782 query name for `ip` against `zone`.
pub fn query_name(ip: IpAddr, zone: &str) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.{zone}")
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(128);
            for byte in v6.octets().iter().rev() {
                let hi = (byte >> 4) & 0xF;
                let lo = byte & 0xF;
                // Low nibble first — RFC 5782 defines the reversed
                // ordering from least significant nibble outward.
                out.push_str(&format!("{lo:x}.{hi:x}."));
            }
            out.push_str(zone);
            out
        }
    }
}

/// Does an A-record reply qualify as a hit for this block?
///
/// The reply's last octet is the list-category index (e.g.
/// `127.0.0.4` → index 4). We hit when bit `index` is set in the
/// configured bitmask. Indexes ≥ 32 never match — they don't fit
/// in a u32 bitmask, and zones don't use them in practice.
pub fn reply_matches(reply_octet: u8, bitmask: u32) -> bool {
    if reply_octet >= 32 {
        return false;
    }
    (1u32 << reply_octet) & bitmask != 0
}

/// Outcome of evaluating *one block* against a query result.
#[derive(Debug, Clone)]
pub enum DnsBlOutcome {
    /// IP isn't listed by this block (or none of the matching
    /// indexes are in the configured bitmask).
    Clean,
    /// Listed; take this action with this mark/reason.
    Hit {
        action: DnsBlAction,
        mark: String,
        zone: String,
    },
}

/// Per-IP cache entry. Holds the *strongest* outcome we found
/// across every block at lookup time. A whitelist hit is recorded
/// as `Clean` — that's what we want to replay on a cache hit too.
#[derive(Debug, Clone)]
struct CacheEntry {
    outcome: Option<DnsBlOutcome>,
    expires: Instant,
}

/// Per-zone counters surfaced via `/STATS D`. Mirrors the per-server
/// counters in nefarious2 dnsbl.c (queries, hits, blocks).
#[derive(Debug, Default)]
pub struct ZoneStats {
    pub queries: AtomicU64,
    pub hits: AtomicU64,
    pub blocks: AtomicU64,
}

/// Process-wide DNSBL state: per-IP cache + global counters + per-zone
/// counters. Lives on `ServerState` and is consulted by the connect path.
#[derive(Debug, Default)]
pub struct DnsblCache {
    cache: DashMap<IpAddr, CacheEntry>,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub total_lookups: AtomicU64,
    pub total_blocks: AtomicU64,
    pub total_marks: AtomicU64,
    pub total_whitelists: AtomicU64,
    /// Per-zone counters, keyed by the configured `name`. We use a
    /// std `RwLock<HashMap>` rather than DashMap because zones are
    /// configured rarely and read on every /STATS D.
    pub zones: std::sync::RwLock<HashMap<String, Arc<ZoneStats>>>,
}

impl DnsblCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn lookup(&self, ip: IpAddr) -> Option<Option<DnsBlOutcome>> {
        let now = Instant::now();
        let entry = self.cache.get(&ip)?;
        if entry.expires <= now {
            let stale_expires = entry.expires;
            drop(entry);
            // Only remove if the entry we saw is still the one in
            // the map — otherwise a concurrent insert may have
            // refreshed it between the read and the remove.
            self.cache
                .remove_if(&ip, |_, e| e.expires == stale_expires);
            return None;
        }
        Some(entry.outcome.clone())
    }

    fn insert(&self, ip: IpAddr, outcome: Option<DnsBlOutcome>, ttl: Duration) {
        self.cache.insert(
            ip,
            CacheEntry {
                outcome,
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Drop expired entries. Cheap O(n) sweep; called on the
    /// 5-minute timer the sweeper task runs.
    pub fn expire(&self) {
        let now = Instant::now();
        self.cache.retain(|_, e| e.expires > now);
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }

    fn zone_stats(&self, name: &str) -> Arc<ZoneStats> {
        if let Some(z) = self.zones.read().ok().and_then(|g| g.get(name).cloned()) {
            return z;
        }
        let mut g = self.zones.write().expect("dnsbl zone stats poisoned");
        g.entry(name.to_string())
            .or_insert_with(|| Arc::new(ZoneStats::default()))
            .clone()
    }
}

/// Spawn a periodic task that sweeps expired cache entries every
/// 5 minutes, matching the cadence of nefarious2's
/// dnsbl_cache_timer. Tied to the server `shutdown` notify so it
/// exits cleanly on /DIE.
pub fn spawn_cache_sweeper(
    cache: Arc<DnsblCache>,
    shutdown: Arc<tokio::sync::Notify>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = tick.tick() => cache.expire(),
                _ = shutdown.notified() => break,
            }
        }
    })
}

/// Resolve one zone for `ip` and return every `127.0.0.X` index we
/// saw in the reply. NXDOMAIN, network errors, and timeouts all
/// produce an empty Vec — we never claim a hit on DNS ambiguity.
async fn resolve_zone(
    resolver: &TokioResolver,
    ip: IpAddr,
    zone: &str,
    timeout: Duration,
) -> Vec<u8> {
    let q = query_name(ip, zone);
    debug!("DNSBL query: {q}");

    let fut = resolver.lookup_ip(q.clone());
    let lookup = match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => {
            debug!("DNSBL {zone}: timeout after {:?}", timeout);
            return Vec::new();
        }
    };

    let ips = match lookup {
        Ok(ips) => ips,
        Err(e) => {
            debug!("DNSBL {zone}: {e}");
            return Vec::new();
        }
    };

    let mut indexes = Vec::new();
    for addr in ips.iter() {
        if let IpAddr::V4(v4) = addr {
            indexes.push(v4.octets()[3]);
        }
    }
    indexes
}

/// Configuration knobs the connect path passes to `check_all`.
/// Keeps the call site terse and lets ServerState own the cache.
pub struct CheckParams {
    pub timeout: Duration,
    pub cache_ttl: Duration,
}

/// Run all configured DNSBL zones against `ip`.
///
/// Returns the strongest applicable outcome:
/// 1. Whitelist hit anywhere → `None` (suppress all blocks/marks).
/// 2. Otherwise the first Block / BlockAll / BlockAnon (if anon) hit.
/// 3. Otherwise the first Mark (or BlockAnon when authed).
/// 4. Otherwise `None`.
///
/// Cache hits short-circuit: if we've seen this IP recently we
/// replay the cached outcome without any DNS work. Cache misses
/// dedupe by zone name so two blocks for the same zone produce
/// one DNS query.
pub async fn check_all(
    resolver: Arc<TokioResolver>,
    cache: Arc<DnsblCache>,
    ip: IpAddr,
    blocks: Vec<DnsBlConfig>,
    is_account: bool,
    params: CheckParams,
) -> Option<DnsBlOutcome> {
    if blocks.is_empty() {
        return None;
    }

    cache.total_lookups.fetch_add(1, Ordering::Relaxed);

    if let Some(cached) = cache.lookup(ip) {
        cache.cache_hits.fetch_add(1, Ordering::Relaxed);
        return cached;
    }
    cache.cache_misses.fetch_add(1, Ordering::Relaxed);

    // Dedupe DNS work: one query per unique zone, then evaluate
    // every block sharing that zone against the returned indexes.
    let mut unique_zones: Vec<String> = Vec::new();
    for b in &blocks {
        if !unique_zones.iter().any(|z| z.eq_ignore_ascii_case(&b.name)) {
            unique_zones.push(b.name.clone());
        }
    }

    let mut tasks = Vec::with_capacity(unique_zones.len());
    for zone in &unique_zones {
        let res = Arc::clone(&resolver);
        let zone_owned = zone.clone();
        let timeout = params.timeout;
        // Bump per-zone query counter at issue time so /STATS D shows
        // attempted lookups even if every reply times out.
        cache.zone_stats(zone).queries.fetch_add(1, Ordering::Relaxed);
        tasks.push(tokio::spawn(async move {
            let idxs = resolve_zone(&res, ip, &zone_owned, timeout).await;
            (zone_owned, idxs)
        }));
    }

    // zone name (lowercased) -> indexes returned
    let mut zone_replies: HashMap<String, Vec<u8>> = HashMap::new();
    for task in tasks {
        match task.await {
            Ok((zone, idxs)) => {
                zone_replies.insert(zone.to_ascii_lowercase(), idxs);
            }
            Err(e) => warn!("DNSBL task panic: {e}"),
        }
    }

    // Collapse blocks against the per-zone replies.
    let mut any_whitelist = false;
    let mut first_block: Option<DnsBlOutcome> = None;
    let mut first_mark: Option<DnsBlOutcome> = None;

    for block in &blocks {
        let key = block.name.to_ascii_lowercase();
        let Some(indexes) = zone_replies.get(&key) else {
            continue;
        };
        let hit = indexes
            .iter()
            .any(|&idx| reply_matches(idx, block.bitmask));
        if !hit {
            continue;
        }

        cache.zone_stats(&block.name).hits.fetch_add(1, Ordering::Relaxed);
        let outcome = DnsBlOutcome::Hit {
            action: block.action,
            mark: block.mark.clone(),
            zone: block.name.clone(),
        };

        match block.action {
            DnsBlAction::Whitelist => {
                any_whitelist = true;
            }
            DnsBlAction::Block | DnsBlAction::BlockAll => {
                if first_block.is_none() {
                    first_block = Some(outcome);
                }
            }
            DnsBlAction::BlockAnon => {
                if !is_account {
                    if first_block.is_none() {
                        first_block = Some(outcome);
                    }
                } else if first_mark.is_none() {
                    // Authed users still get marked when the
                    // block_anon zone fires — they're allowed in
                    // but opers see the flag. Translate the action
                    // to Mark so the connect-path caller's match
                    // doesn't have to know the is_account state.
                    first_mark = Some(DnsBlOutcome::Hit {
                        action: DnsBlAction::Mark,
                        mark: block.mark.clone(),
                        zone: block.name.clone(),
                    });
                }
            }
            DnsBlAction::Mark => {
                if first_mark.is_none() {
                    first_mark = Some(outcome);
                }
            }
        }
    }

    let final_outcome = if any_whitelist {
        cache.total_whitelists.fetch_add(1, Ordering::Relaxed);
        None
    } else if let Some(b) = first_block {
        cache.total_blocks.fetch_add(1, Ordering::Relaxed);
        if let DnsBlOutcome::Hit { ref zone, .. } = b {
            cache.zone_stats(zone).blocks.fetch_add(1, Ordering::Relaxed);
        }
        Some(b)
    } else if let Some(m) = first_mark {
        cache.total_marks.fetch_add(1, Ordering::Relaxed);
        Some(m)
    } else {
        None
    };

    cache.insert(ip, final_outcome.clone(), params.cache_ttl);
    final_outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn query_name_ipv4_reverses_octets() {
        let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        assert_eq!(query_name(ip, "zen.spamhaus.org"), "4.3.2.1.zen.spamhaus.org");
    }

    #[test]
    fn query_name_ipv6_reverses_nibbles() {
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        let name = query_name(ip, "example.org");
        assert!(name.starts_with("1.0.0.0."));
        assert!(name.ends_with(".example.org"));
        assert_eq!(name.len(), 32 * 2 + "example.org".len());
    }

    #[test]
    fn reply_matches_uses_index_into_bitmask() {
        // `host = "2,3,4,5,6,7,9"` → bits 2..=7 + 9.
        let mask = (1u32 << 2) | (1 << 3) | (1 << 4) | (1 << 5)
            | (1 << 6) | (1 << 7) | (1 << 9);
        assert!(reply_matches(2, mask));
        assert!(reply_matches(4, mask));
        assert!(reply_matches(9, mask));
        assert!(!reply_matches(8, mask));
        assert!(!reply_matches(10, mask));
        assert!(!reply_matches(0, mask));
        // Indexes that don't fit in a u32 must never match.
        assert!(!reply_matches(32, 0xFFFF_FFFF));
        assert!(!reply_matches(255, 0xFFFF_FFFF));
    }

    #[test]
    fn reply_matches_match_all_bitmask() {
        // Default bitmask (no `host` / `bitmask` configured).
        assert!(reply_matches(2, 0xFFFF_FFFF));
        assert!(reply_matches(31, 0xFFFF_FFFF));
        assert!(!reply_matches(32, 0xFFFF_FFFF));
    }

    #[test]
    fn cache_round_trip() {
        let cache = DnsblCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        assert!(cache.lookup(ip).is_none());
        cache.insert(ip, None, Duration::from_secs(60));
        assert!(matches!(cache.lookup(ip), Some(None)));
        let hit = DnsBlOutcome::Hit {
            action: DnsBlAction::Block,
            mark: "x".into(),
            zone: "z.example".into(),
        };
        cache.insert(ip, Some(hit), Duration::from_secs(60));
        assert!(matches!(cache.lookup(ip), Some(Some(DnsBlOutcome::Hit { .. }))));
    }

    #[test]
    fn cache_expires() {
        let cache = DnsblCache::new();
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
        cache.insert(ip, None, Duration::from_millis(0));
        // Past-due entry must be reaped on lookup.
        std::thread::sleep(Duration::from_millis(1));
        assert!(cache.lookup(ip).is_none());
        assert_eq!(cache.cache_size(), 0);
    }
}
