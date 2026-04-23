//! DNSBL (DNS-based blackhole list) checks at connect time.
//!
//! For each configured `DnsBL {}` block we build an RFC 5782 query
//! name — octet-reversed IPv4 like `4.3.2.1.<zone>` or
//! nibble-reversed IPv6 — and resolve it through the same
//! hickory-resolver instance the reverse-DNS path uses. A
//! successful lookup means the IP is listed; the block's action
//! decides whether to disconnect, mark, or whitelist the client.
//!
//! The lookup runs in a spawned task and doesn't gate registration.
//! When the result arrives, if the action is Block we drive a
//! disconnect via the client's existing signal channel. This
//! mirrors nefarious2 dnsbl.c's async design: the client connects
//! normally and the listing action fires when the DNS reply lands.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use tracing::{debug, info, warn};

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

/// Check `reply_octet` (the last byte of the returned A record)
/// against the mask. `None` mask accepts any reply; otherwise at
/// least one bit must be set in both.
pub fn reply_matches(reply_octet: u8, mask: Option<u8>) -> bool {
    match mask {
        Some(m) => (reply_octet & m) != 0,
        None => true,
    }
}

/// Result of one zone's lookup.
#[derive(Debug, Clone)]
pub enum DnsBlOutcome {
    /// IP isn't listed (or zone didn't match).
    Clean,
    /// Listed; take this action with this reason.
    Hit {
        action: DnsBlAction,
        reason: String,
        zone: String,
    },
}

/// Query one DNSBL zone for `ip`. Returns `Clean` on NXDOMAIN or
/// network timeout (i.e. we never claim a hit when we're not sure).
/// Uses a short per-query timeout so one slow zone can't hold up
/// the connect path indefinitely.
pub async fn lookup(
    resolver: &TokioResolver,
    ip: IpAddr,
    block: &DnsBlConfig,
) -> DnsBlOutcome {
    let q = query_name(ip, &block.domain);
    debug!("DNSBL query: {q}");

    let fut = resolver.lookup_ip(q.clone());
    let lookup = match tokio::time::timeout(Duration::from_secs(5), fut).await {
        Ok(r) => r,
        Err(_) => {
            debug!("DNSBL {zone}: timeout", zone = block.domain);
            return DnsBlOutcome::Clean;
        }
    };

    let ips = match lookup {
        Ok(ips) => ips,
        Err(e) => {
            // NXDOMAIN / no records → not listed. Network errors
            // also fall here; we fail open rather than refuse
            // connections on DNS hiccups.
            debug!("DNSBL {zone}: {e}", zone = block.domain);
            return DnsBlOutcome::Clean;
        }
    };

    // Inspect the last octet of each A record. Any matching
    // record is a hit — DNSBL zones encode reason codes in the
    // last octet (127.0.0.2 for spam, .4 for exploits, etc.).
    for addr in ips.iter() {
        if let IpAddr::V4(v4) = addr {
            let last = v4.octets()[3];
            if reply_matches(last, block.reply_mask) {
                info!(
                    "DNSBL hit: {ip} on {zone} (reply 127.0.0.{last})",
                    zone = block.domain
                );
                return DnsBlOutcome::Hit {
                    action: block.action,
                    reason: block.reason.clone(),
                    zone: block.domain.clone(),
                };
            }
        }
    }

    DnsBlOutcome::Clean
}

/// Run all configured DNSBL zones against `ip` in parallel. Returns
/// the first blocking hit, or None if every zone came back clean /
/// whitelisted / Mark-only. Whitelist matches short-circuit — if
/// any whitelist zone lists the IP, no other hits apply.
pub async fn check_all(
    resolver: Arc<TokioResolver>,
    ip: IpAddr,
    blocks: Vec<DnsBlConfig>,
    is_account: bool,
) -> Option<DnsBlOutcome> {
    if blocks.is_empty() {
        return None;
    }

    // Kick off every lookup concurrently. The per-query timeout
    // bounds the worst case; a dead zone won't delay the rest.
    let mut tasks = Vec::with_capacity(blocks.len());
    for block in &blocks {
        let res = Arc::clone(&resolver);
        let block = block.clone();
        tasks.push(tokio::spawn(async move { lookup(&res, ip, &block).await }));
    }

    let mut any_whitelist = false;
    let mut first_block: Option<DnsBlOutcome> = None;
    let mut first_mark: Option<DnsBlOutcome> = None;

    for task in tasks {
        let outcome = match task.await {
            Ok(o) => o,
            Err(e) => {
                warn!("DNSBL task panic: {e}");
                continue;
            }
        };
        match &outcome {
            DnsBlOutcome::Clean => {}
            DnsBlOutcome::Hit { action, .. } => match action {
                DnsBlAction::Whitelist => {
                    any_whitelist = true;
                }
                DnsBlAction::Block => {
                    if first_block.is_none() {
                        first_block = Some(outcome);
                    }
                }
                DnsBlAction::BlockAnon => {
                    if !is_account && first_block.is_none() {
                        first_block = Some(outcome);
                    } else if is_account && first_mark.is_none() {
                        // Authed users still get marked when the
                        // block_anon zone fires — they're allowed
                        // in but opers see the flag.
                        first_mark = Some(outcome);
                    }
                }
                DnsBlAction::Mark => {
                    if first_mark.is_none() {
                        first_mark = Some(outcome);
                    }
                }
            },
        }
    }

    // Whitelist beats any block. Mark only applies when nothing
    // blocks.
    if any_whitelist {
        return None;
    }
    first_block.or(first_mark)
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
        assert!(name.starts_with("1.0.0.0.")); // trailing ::1
        assert!(name.ends_with(".example.org"));
        // Full length: 32 nibbles × 2 chars ("x.") + "example.org".
        assert_eq!(name.len(), 32 * 2 + "example.org".len());
    }

    #[test]
    fn reply_mask_matches_correctly() {
        // No mask: anything hits.
        assert!(reply_matches(2, None));
        assert!(reply_matches(0, None));
        // Exact mask: only when a bit in common.
        assert!(reply_matches(0x02, Some(0x02)));
        assert!(!reply_matches(0x04, Some(0x02)));
        assert!(reply_matches(0x06, Some(0x02))); // both bits set
    }
}
