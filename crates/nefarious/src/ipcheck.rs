//! Per-IP connection throttling.
//!
//! Mirrors the intent of nefarious2's IPcheck module (ircd_res.c /
//! ipcheck.c): cap how many connections a single IP can make in a
//! rolling time window. Prevents a misbehaving client or botnet
//! from exhausting the server's connection-handling capacity.
//!
//! Implementation is a DashMap keyed on `IpAddr`, with each entry
//! holding the count of recent attempts and the start time of the
//! current window. On a new attempt we either refresh the window
//! (if it's aged out), bump the counter, and decide whether to
//! refuse. A periodic prune sweep would be needed for very large
//! deployments — a lazy per-lookup staleness check covers the
//! normal case without a background task.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;

/// One IP's recent-connection history. `count` is the number of
/// attempts accepted since `window_start`; once `window_start +
/// period` has passed, the next check resets both.
#[derive(Debug, Clone, Copy)]
pub struct IpCheckEntry {
    pub count: u32,
    pub window_start: Instant,
}

#[derive(Debug, Default)]
pub struct IpCheck {
    entries: DashMap<IpAddr, IpCheckEntry>,
}

impl IpCheck {
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Record a connection attempt from `ip` and decide whether to
    /// accept it. Returns `Ok(())` when under the limit, or
    /// `Err(count_at_refusal)` when the caller should refuse.
    ///
    /// Loopback (127.0.0.0/8, ::1) is always allowed; integration
    /// test rigs and local health checks shouldn't hit the cap.
    pub fn record(
        &self,
        ip: IpAddr,
        limit: u32,
        period: Duration,
    ) -> Result<(), u32> {
        if ip.is_loopback() {
            return Ok(());
        }
        let now = Instant::now();
        let mut entry = self.entries.entry(ip).or_insert(IpCheckEntry {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) > period {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
        if entry.count > limit {
            return Err(entry.count);
        }
        Ok(())
    }

    /// Drop the per-IP entry. Called on clean disconnect so a
    /// well-behaved client doesn't keep burning against the cap
    /// after closing. Only decrements the count rather than
    /// removing, so rapid reconnect still runs into the ceiling if
    /// it shows up again in the same window.
    pub fn release(&self, ip: IpAddr) {
        if let Some(mut entry) = self.entries.get_mut(&ip) {
            entry.count = entry.count.saturating_sub(1);
            if entry.count == 0 {
                drop(entry);
                self.entries.remove(&ip);
            }
        }
    }
}
