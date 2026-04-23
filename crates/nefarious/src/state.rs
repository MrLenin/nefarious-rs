use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use hickory_resolver::TokioResolver;
use tokio::sync::RwLock;

use irc_config::Config;
use irc_proto::irc_casefold;
use p10_proto::{ClientNumeric, ServerNumeric};

use crate::capabilities::{Capability, default_advertised_caps};
use crate::channel::Channel;
use crate::client::{Client, ClientId};
use crate::s2s::types::{BouncerSession, RemoteClient, RemoteServer, ServerLink};

/// P10 client numerics are the 3-char tail of a 5-char YYXXX id, i.e. 18
/// bits, 262144 slots per server. Previously we derived the numeric from
/// the monotonically-increasing `ClientId.0 as u32`, which wraps and
/// collides after the 262144th connection on a long-running server. This
/// allocator recycles slots by maintaining a stack of released numerics.
#[derive(Debug)]
pub struct NumericAllocator {
    next: u32,
    freed: Vec<u32>,
    max: u32,
}

impl NumericAllocator {
    pub fn new() -> Self {
        // Slot 0 is reserved for "no numeric yet"; real numerics start at 1.
        Self {
            next: 1,
            freed: Vec::new(),
            max: 1 << 18,
        }
    }

    /// Returns a fresh or recycled slot, or None if the 18-bit space is
    /// full. The caller should refuse the connection in that case — it
    /// matches what the C server does (no numeric → no P10 introduction).
    pub fn allocate(&mut self) -> Option<u32> {
        if let Some(n) = self.freed.pop() {
            return Some(n);
        }
        if self.next < self.max {
            let n = self.next;
            self.next += 1;
            return Some(n);
        }
        None
    }

    pub fn release(&mut self, numeric: u32) {
        if numeric > 0 && numeric < self.max {
            self.freed.push(numeric);
        }
    }
}

impl Default for NumericAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod allocator_tests {
    use super::NumericAllocator;

    #[test]
    fn fresh_slots_are_sequential_starting_at_one() {
        let mut a = NumericAllocator::new();
        assert_eq!(a.allocate(), Some(1));
        assert_eq!(a.allocate(), Some(2));
        assert_eq!(a.allocate(), Some(3));
    }

    #[test]
    fn released_slots_are_reused_before_growing() {
        let mut a = NumericAllocator::new();
        let x = a.allocate().unwrap();
        let y = a.allocate().unwrap();
        let z = a.allocate().unwrap();
        a.release(y);
        // Next allocation reuses y rather than handing out 4.
        assert_eq!(a.allocate(), Some(y));
        assert_ne!(a.allocate(), Some(z));
    }

    #[test]
    fn returns_none_when_exhausted() {
        let mut a = NumericAllocator::new();
        // Shrink the pool so the test doesn't have to allocate 262k slots.
        a.max = 3;
        assert_eq!(a.allocate(), Some(1));
        assert_eq!(a.allocate(), Some(2));
        assert_eq!(a.allocate(), None);
        a.release(1);
        assert_eq!(a.allocate(), Some(1));
        assert_eq!(a.allocate(), None);
    }

    #[test]
    fn release_outside_range_is_ignored() {
        let mut a = NumericAllocator::new();
        a.max = 5;
        a.release(0); // reserved slot
        a.release(99); // outside pool
        assert_eq!(a.allocate(), Some(1));
    }
}

/// Shared server state, passed around via `Arc<ServerState>`.
pub struct ServerState {
    /// Server name from config.
    pub server_name: String,
    /// Server description.
    pub server_description: String,
    /// Server creation time.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Server start timestamp (epoch seconds, for P10).
    pub start_timestamp: u64,
    /// Server version string.
    pub version: String,

    // --- Local state ---
    /// Connected local clients by ID.
    pub clients: DashMap<ClientId, Arc<RwLock<Client>>>,
    /// Nick → ClientId mapping (case-insensitive, stored lowercase).
    pub nicks: DashMap<String, ClientId>,
    /// Channels by name (case-insensitive, stored lowercase).
    pub channels: DashMap<String, Arc<RwLock<Channel>>>,
    /// Pool of 18-bit P10 client numerics, per server.
    pub numeric_allocator: Mutex<NumericAllocator>,
    /// ClientId → allocated P10 numeric, for synchronous lookup from
    /// routing/burst paths without taking the Client's RwLock.
    pub client_numerics: DashMap<ClientId, u32>,

    // --- P10 / S2S state ---
    /// Our P10 server numeric.
    pub numeric: ServerNumeric,
    /// Remote servers by numeric.
    pub remote_servers: DashMap<ServerNumeric, Arc<RwLock<RemoteServer>>>,
    /// Remote clients by numeric.
    pub remote_clients: DashMap<ClientNumeric, Arc<RwLock<RemoteClient>>>,
    /// Nick → ClientNumeric mapping for remote users (case-insensitive).
    pub remote_nicks: DashMap<String, ClientNumeric>,
    /// Active server links by numeric.
    pub links: DashMap<ServerNumeric, Arc<ServerLink>>,
    /// Bouncer sessions by (account, sessid). Populated from P10 BS
    /// tokens during burst and steady state. Keeps the session→primary
    /// mapping that BX P (numeric swap) consults during a session
    /// transfer. Keyed case-sensitively since sessids are opaque.
    pub bouncer_sessions: DashMap<(String, String), BouncerSession>,

    /// Server configuration.
    pub config: Arc<Config>,
    /// MOTD lines.
    pub motd: Vec<String>,
    /// Shared DNS resolver for reverse-lookup of connecting clients.
    /// `None` when the system DNS configuration could not be parsed at
    /// startup (we log a warning and fall back to IP-as-host).
    pub dns_resolver: Option<Arc<TokioResolver>>,
    /// IRCv3 capabilities the server currently advertises. Built once at
    /// startup from `default_advertised_caps`; each Phase 2 sub-phase
    /// flips a new cap on as its behaviour ships. A REQ for a cap not in
    /// this set gets NAK'd.
    pub advertised_caps: std::collections::HashSet<Capability>,
    /// Authentication backend. SASL mechanisms in Phase 3.2+ and IAuth
    /// in 3.6 call into this trait; the default built-in is an empty
    /// in-memory store. Wrapped in an Arc so handlers can clone a
    /// reference without borrowing ServerState for the await duration.
    pub account_store: crate::accounts::SharedAccountStore,
    /// Ring buffer of recently-departed users, keyed in insertion
    /// order so /WHOWAS returns the most recent first. Soft-capped
    /// at `WHOWAS_MAX`; oldest entries evict when full. Matches the
    /// `whowas_history` in nefarious2/ircd/whowas.c — one bounded
    /// table per server.
    pub whowas: tokio::sync::Mutex<std::collections::VecDeque<WhowasEntry>>,
    /// IRCv3 MONITOR reverse index: casefolded nick → clients that
    /// asked to be notified when that nick comes online or goes
    /// offline. Every `Client.monitored` add/remove keeps this in
    /// sync. Lookup in the client-lifecycle paths is O(1); without
    /// the reverse index we'd have to scan every client on every
    /// quit/register.
    pub monitored_by: DashMap<String, std::collections::HashSet<ClientId>>,
    /// Dalnet WATCH reverse index — symmetric to `monitored_by` but
    /// keyed for clients using the `/WATCH` command surface. Same
    /// lifecycle hooks fire to both; which numerics a watcher sees
    /// depends on which index they're in for the given nick.
    pub watched_by: DashMap<String, std::collections::HashSet<ClientId>>,
    /// Active + suspended G-line set, keyed by lowercased mask.
    /// Shared by inbound GL handling, enforcement on connect, and
    /// outbound burst emission.
    pub glines: crate::gline::GlineStore,
}

/// One past-user record kept for `/WHOWAS` lookups.
#[derive(Debug, Clone)]
pub struct WhowasEntry {
    pub nick: String,
    pub user: String,
    pub host: String,
    pub realname: String,
    pub server: String,
    pub quit_at: chrono::DateTime<chrono::Utc>,
}

/// Soft cap on retained WHOWAS entries — matches a common
/// nefarious/ircu default. Callers can override if they ever want
/// runtime-tunable history depth.
pub const WHOWAS_MAX: usize = 500;

impl ServerState {
    pub fn new(config: Config) -> Self {
        let now = chrono::Utc::now();
        let dns_resolver = match crate::dns::build_resolver() {
            Ok(r) => Some(Arc::new(r)),
            Err(e) => {
                tracing::warn!(
                    "could not build DNS resolver from system config: {e}; reverse DNS disabled"
                );
                None
            }
        };
        Self {
            server_name: config.general.name.clone(),
            server_description: config.general.description.clone(),
            created_at: now,
            start_timestamp: now.timestamp() as u64,
            version: format!("nefarious-rs-{}", env!("CARGO_PKG_VERSION")),
            clients: DashMap::new(),
            nicks: DashMap::new(),
            channels: DashMap::new(),
            numeric_allocator: Mutex::new(NumericAllocator::new()),
            client_numerics: DashMap::new(),
            numeric: ServerNumeric(config.general.numeric),
            remote_servers: DashMap::new(),
            remote_clients: DashMap::new(),
            remote_nicks: DashMap::new(),
            links: DashMap::new(),
            bouncer_sessions: DashMap::new(),
            config: Arc::new(config),
            motd: vec![
                "Welcome to nefarious-rs".to_string(),
                "A Rust implementation of Nefarious IRCd".to_string(),
            ],
            dns_resolver,
            advertised_caps: default_advertised_caps(),
            account_store: crate::accounts::empty_in_memory(),
            whowas: tokio::sync::Mutex::new(std::collections::VecDeque::with_capacity(WHOWAS_MAX)),
            monitored_by: DashMap::new(),
            watched_by: DashMap::new(),
            glines: DashMap::new(),
        }
    }

    /// Push a WHOWAS entry onto the history ring, evicting the
    /// oldest if the buffer is at capacity. Called from the client
    /// disconnect path on ServerState::remove_client.
    pub async fn record_whowas(&self, entry: WhowasEntry) {
        let mut buf = self.whowas.lock().await;
        if buf.len() >= WHOWAS_MAX {
            buf.pop_front();
        }
        buf.push_back(entry);
    }

    /// Add a nick to a client's MONITOR watch list. Updates both
    /// sides of the index so the per-nick reverse lookup stays in
    /// sync. Returns `true` if the nick was newly added.
    pub async fn monitor_add(&self, watcher: ClientId, nick: &str) -> bool {
        let key = irc_casefold(nick);
        // Side A: the client's own list.
        let inserted_on_client = if let Some(client) = self.clients.get(&watcher) {
            let mut c = client.write().await;
            c.monitored.insert(key.clone())
        } else {
            false
        };
        // Side B: the reverse index.
        self.monitored_by
            .entry(key)
            .or_default()
            .insert(watcher);
        inserted_on_client
    }

    /// Remove a nick from a client's MONITOR watch list; symmetric
    /// with `monitor_add`. Prunes empty reverse-index entries.
    pub async fn monitor_remove(&self, watcher: ClientId, nick: &str) {
        let key = irc_casefold(nick);
        if let Some(client) = self.clients.get(&watcher) {
            client.write().await.monitored.remove(&key);
        }
        if let Some(mut entry) = self.monitored_by.get_mut(&key) {
            entry.remove(&watcher);
            if entry.is_empty() {
                drop(entry);
                self.monitored_by.remove(&key);
            }
        }
    }

    /// Clear a client's entire MONITOR list. Used on `MONITOR C` and
    /// on client disconnect.
    pub async fn monitor_clear(&self, watcher: ClientId) {
        let nicks: Vec<String> = if let Some(client) = self.clients.get(&watcher) {
            let c = client.read().await;
            c.monitored.iter().cloned().collect()
        } else {
            return;
        };
        for nick in &nicks {
            self.monitor_remove(watcher, nick).await;
        }
    }

    /// Symmetric with `monitor_add` but keyed into `watched_by` for
    /// the `/WATCH` surface. Returns whether the nick was newly
    /// inserted on this client's side.
    pub async fn watch_add(&self, watcher: ClientId, nick: &str) -> bool {
        let key = irc_casefold(nick);
        let inserted_on_client = if let Some(client) = self.clients.get(&watcher) {
            let mut c = client.write().await;
            c.watched.insert(key.clone())
        } else {
            false
        };
        self.watched_by
            .entry(key)
            .or_default()
            .insert(watcher);
        inserted_on_client
    }

    /// Remove a nick from a client's WATCH list. Mirrors
    /// `monitor_remove` shape.
    pub async fn watch_remove(&self, watcher: ClientId, nick: &str) {
        let key = irc_casefold(nick);
        if let Some(client) = self.clients.get(&watcher) {
            client.write().await.watched.remove(&key);
        }
        if let Some(mut entry) = self.watched_by.get_mut(&key) {
            entry.remove(&watcher);
            if entry.is_empty() {
                drop(entry);
                self.watched_by.remove(&key);
            }
        }
    }

    /// Clear a client's entire WATCH list. Called on `/WATCH C` and
    /// on client disconnect alongside `monitor_clear`.
    pub async fn watch_clear(&self, watcher: ClientId) {
        let nicks: Vec<String> = if let Some(client) = self.clients.get(&watcher) {
            let c = client.read().await;
            c.watched.iter().cloned().collect()
        } else {
            return;
        };
        for nick in &nicks {
            self.watch_remove(watcher, nick).await;
        }
    }

    /// Emit the online-style notification (730 MONITOR / 604 WATCH)
    /// to every client watching `nick` under either surface. `nick`
    /// is the display form (preserved case), `user`/`host` feed the
    /// WATCH numeric's parameter slots, and `last_ts` is a best-effort
    /// "last known activity" timestamp used to fill WATCH's last-nick
    /// / last-time field.
    pub async fn notify_monitor_online(&self, nick: &str, prefix: &str) {
        let key = irc_casefold(nick);
        // MONITOR watchers: 730 RPL_MONONLINE with the full prefix.
        if let Some(e) = self.monitored_by.get(&key) {
            let watchers: Vec<ClientId> = e.iter().copied().collect();
            drop(e);
            for watcher_id in watchers {
                if let Some(client) = self.clients.get(&watcher_id) {
                    let c = client.read().await;
                    c.send(irc_proto::Message::with_source(
                        &self.server_name,
                        irc_proto::Command::Numeric(crate::numeric::RPL_MONONLINE),
                        vec![c.nick.clone(), prefix.to_string()],
                    ));
                }
            }
        }
        // WATCH watchers: 604 RPL_NOWON. Split the prefix into its
        // nick!user@host components for the numeric's param slots.
        if let Some(e) = self.watched_by.get(&key) {
            let watchers: Vec<ClientId> = e.iter().copied().collect();
            drop(e);
            let (user, host) = split_user_host(prefix).unwrap_or(("*", "*"));
            let lasttime = chrono::Utc::now().timestamp().to_string();
            for watcher_id in watchers {
                if let Some(client) = self.clients.get(&watcher_id) {
                    let c = client.read().await;
                    c.send(irc_proto::Message::with_source(
                        &self.server_name,
                        irc_proto::Command::Numeric(crate::numeric::RPL_NOWON),
                        vec![
                            c.nick.clone(),
                            nick.to_string(),
                            user.to_string(),
                            host.to_string(),
                            lasttime.clone(),
                            "is online".into(),
                        ],
                    ));
                }
            }
        }
    }

    /// Emit the offline-style notification (731 MONITOR / 605 WATCH).
    pub async fn notify_monitor_offline(&self, nick: &str) {
        let key = irc_casefold(nick);
        if let Some(e) = self.monitored_by.get(&key) {
            let watchers: Vec<ClientId> = e.iter().copied().collect();
            drop(e);
            for watcher_id in watchers {
                if let Some(client) = self.clients.get(&watcher_id) {
                    let c = client.read().await;
                    c.send(irc_proto::Message::with_source(
                        &self.server_name,
                        irc_proto::Command::Numeric(crate::numeric::RPL_MONOFFLINE),
                        vec![c.nick.clone(), nick.to_string()],
                    ));
                }
            }
        }
        if let Some(e) = self.watched_by.get(&key) {
            let watchers: Vec<ClientId> = e.iter().copied().collect();
            drop(e);
            let lasttime = chrono::Utc::now().timestamp().to_string();
            for watcher_id in watchers {
                if let Some(client) = self.clients.get(&watcher_id) {
                    let c = client.read().await;
                    c.send(irc_proto::Message::with_source(
                        &self.server_name,
                        irc_proto::Command::Numeric(crate::numeric::RPL_NOWOFF),
                        vec![
                            c.nick.clone(),
                            nick.to_string(),
                            "*".into(),
                            "*".into(),
                            lasttime.clone(),
                            "is offline".into(),
                        ],
                    ));
                }
            }
        }
    }

    /// Atomically reserve `nick` for `id`. Returns true if reserved (or
    /// already held by the same id — idempotent), false if held by a
    /// different local or remote user.
    ///
    /// Used during registration and nick change to close the TOCTOU window
    /// between "is this nick taken?" and "take this nick".
    pub fn try_reserve_nick(&self, nick: &str, id: ClientId) -> bool {
        let key = irc_casefold(nick);
        if self.remote_nicks.contains_key(&key) {
            return false;
        }
        match self.nicks.entry(key) {
            dashmap::Entry::Occupied(entry) => *entry.get() == id,
            dashmap::Entry::Vacant(entry) => {
                entry.insert(id);
                true
            }
        }
    }

    /// Release a nick reservation, but only if it still points at `id`.
    /// Called when a client disconnects before completing registration or
    /// when a nick change supersedes the old nick.
    pub fn release_nick(&self, nick: &str, id: ClientId) {
        let key = irc_casefold(nick);
        self.nicks.remove_if(&key, |_, v| *v == id);
    }

    /// Register a client (after NICK+USER complete). The nick must already
    /// have been reserved via `try_reserve_nick` and the P10 numeric
    /// allocated via `try_allocate_numeric`.
    pub async fn register_client(&self, client: Arc<RwLock<Client>>, _nick: &str) {
        let id = {
            let c = client.read().await;
            c.id
        };
        self.clients.insert(id, client);
    }

    /// Search the G-line store for the first currently-enforceable
    /// entry whose mask matches the given `user@host`. Returns a
    /// snapshot (mask + reason) so callers don't have to hold the
    /// lock across the client disconnect path. Inactive/expired
    /// entries are skipped.
    pub async fn find_matching_gline(&self, user_host: &str) -> Option<(String, String)> {
        let now = chrono::Utc::now();
        for entry in self.glines.iter() {
            let gl = entry.value().read().await;
            if gl.is_enforceable(now) && gl.matches(user_host) {
                return Some((gl.mask.clone(), gl.reason.clone()));
            }
        }
        None
    }

    /// Allocate a P10 client numeric and record it against `id`. Returns
    /// None when the 18-bit slot space is exhausted (the caller should
    /// then refuse the connection).
    pub fn try_allocate_numeric(&self, id: ClientId) -> Option<u32> {
        let n = self
            .numeric_allocator
            .lock()
            .expect("numeric allocator mutex poisoned")
            .allocate()?;
        self.client_numerics.insert(id, n);
        Some(n)
    }

    /// Release a previously-allocated P10 numeric back to the pool. Safe
    /// to call twice; the second call is a no-op because the mapping has
    /// already been removed.
    pub fn release_numeric(&self, id: ClientId) {
        if let Some((_, n)) = self.client_numerics.remove(&id) {
            self.numeric_allocator
                .lock()
                .expect("numeric allocator mutex poisoned")
                .release(n);
        }
    }

    /// Look up the P10 numeric for a local client, if any.
    pub fn numeric_for(&self, id: ClientId) -> Option<u32> {
        self.client_numerics.get(&id).map(|e| *e)
    }

    /// Reverse of `numeric_for`: given a P10 client numeric slot,
    /// return the owning local `ClientId`. O(n) scan over the local
    /// client table; callers are expected to hit this rarely (remote
    /// KICK/KILL/INVITE resolution where the s2s peer refers to one
    /// of our users by their 5-char numeric).
    pub fn client_by_numeric_slot(&self, slot: u32) -> Option<ClientId> {
        self.client_numerics
            .iter()
            .find(|e| *e.value() == slot)
            .map(|e| *e.key())
    }

    /// Remove a client entirely.
    pub async fn remove_client(&self, id: ClientId) {
        // Release the P10 numeric before anything else — safe even if the
        // client entry is gone (release_numeric is a no-op on a missing
        // mapping).
        self.release_numeric(id);

        // Capture WHOWAS metadata before we drop the Client entry —
        // /WHOWAS looks up users *after* they've disconnected.
        let (nick, display_nick, whowas_entry) = {
            if let Some(client) = self.clients.get(&id) {
                let c = client.read().await;
                let folded = irc_casefold(&c.nick);
                let display = c.nick.clone();
                let entry = WhowasEntry {
                    nick: c.nick.clone(),
                    user: c.user.clone(),
                    host: c.host.clone(),
                    realname: c.realname.clone(),
                    server: self.server_name.clone(),
                    quit_at: chrono::Utc::now(),
                };
                (folded, display, entry)
            } else {
                return;
            }
        };
        self.record_whowas(whowas_entry).await;
        self.nicks.remove_if(&nick, |_, v| *v == id);

        // IRCv3 MONITOR: notify watchers this nick is now offline.
        // Also drop this client's own MONITOR subscriptions so the
        // reverse index doesn't carry stale watchers.
        self.notify_monitor_offline(&display_nick).await;
        self.monitor_clear(id).await;
        self.watch_clear(id).await;

        // Remove from all channels
        let mut empty_channels = Vec::new();
        for entry in self.channels.iter() {
            let mut chan = entry.value().write().await;
            chan.remove_member(&id);
            if chan.is_empty() {
                empty_channels.push(entry.key().clone());
            }
        }

        // Clean up empty channels
        for name in empty_channels {
            self.channels.remove(&name);
        }

        // Remove client
        self.clients.remove(&id);
    }

    /// Look up a client by nick (rfc1459-case-insensitive).
    pub fn find_client_by_nick(&self, nick: &str) -> Option<Arc<RwLock<Client>>> {
        let id = self.nicks.get(&irc_casefold(nick))?;
        let client = self.clients.get(&*id)?;
        Some(Arc::clone(client.value()))
    }

    /// Get or create a channel.
    pub fn get_or_create_channel(&self, name: &str) -> Arc<RwLock<Channel>> {
        let key = irc_casefold(name);
        self.channels
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(Channel::new(name.to_string()))))
            .value()
            .clone()
    }

    /// Get a channel if it exists.
    pub fn get_channel(&self, name: &str) -> Option<Arc<RwLock<Channel>>> {
        self.channels
            .get(&irc_casefold(name))
            .map(|e| e.value().clone())
    }

    /// Get the number of connected clients.
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }

    /// Get the number of channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    // --- Remote (S2S) methods ---

    /// Register a remote client from P10 NICK burst.
    pub fn register_remote_client(&self, client: Arc<RwLock<RemoteClient>>, nick: &str, numeric: ClientNumeric) {
        self.remote_nicks.insert(irc_casefold(nick), numeric);
        self.remote_clients.insert(numeric, client);
    }

    /// Register a remote alias for a bouncer session. Aliases share
    /// identity with their primary but are network-invisible: they
    /// live in `remote_clients` only so MODE/KICK/PART for their
    /// numeric stay addressable, but are NOT inserted into
    /// `remote_nicks` and are filtered from NAMES/WHO responses.
    pub fn register_remote_alias(&self, client: Arc<RwLock<RemoteClient>>, numeric: ClientNumeric) {
        self.remote_clients.insert(numeric, client);
    }

    /// Remove a remote client (QUIT, KILL, SQUIT).
    pub async fn remove_remote_client(&self, numeric: ClientNumeric) {
        let (nick_folded, display_nick, is_alias) = {
            if let Some(client) = self.remote_clients.get(&numeric) {
                let c = client.read().await;
                (irc_casefold(&c.nick), c.nick.clone(), c.is_alias)
            } else {
                return;
            }
        };
        self.remote_nicks.remove(&nick_folded);

        // IRCv3 MONITOR: notify local watchers that this remote nick
        // went offline. Aliases are network-invisible so their
        // departure doesn't fire a notification — the primary is the
        // visible entity that watchers track.
        if !is_alias {
            self.notify_monitor_offline(&display_nick).await;
        }
        let _ = nick_folded; // keep alive for the remainder of the fn

        // Remove from all channels
        let mut empty_channels = Vec::new();
        for entry in self.channels.iter() {
            let mut chan = entry.value().write().await;
            chan.remote_members.remove(&numeric);
            if chan.is_empty() {
                empty_channels.push(entry.key().clone());
            }
        }

        for name in empty_channels {
            self.channels.remove(&name);
        }

        self.remote_clients.remove(&numeric);
    }

    /// Remove all remote clients belonging to a server (for SQUIT).
    pub async fn remove_remote_server(&self, server_numeric: ServerNumeric) {
        // Collect all client numerics for this server
        let to_remove: Vec<ClientNumeric> = self
            .remote_clients
            .iter()
            .filter(|entry| entry.key().server == server_numeric)
            .map(|entry| *entry.key())
            .collect();

        for numeric in to_remove {
            self.remove_remote_client(numeric).await;
        }

        self.remote_servers.remove(&server_numeric);
        self.links.remove(&server_numeric);
    }

    /// Remove a channel from the registry if it has no local or remote members.
    /// Call this after any operation that reduces a channel's membership.
    pub async fn reap_channel_if_empty(&self, chan_name: &str) {
        let key = irc_casefold(chan_name);
        if let Some(entry) = self.channels.get(&key) {
            if entry.value().read().await.is_empty() {
                drop(entry);
                self.channels.remove(&key);
            }
        }
    }

    /// Find a remote client by nick (rfc1459-case-insensitive).
    pub fn find_remote_by_nick(&self, nick: &str) -> Option<Arc<RwLock<RemoteClient>>> {
        let numeric = self.remote_nicks.get(&irc_casefold(nick))?;
        let client = self.remote_clients.get(&*numeric)?;
        Some(Arc::clone(client.value()))
    }

    /// Check if a nick is in use by either a local or remote user.
    pub fn nick_in_use(&self, nick: &str) -> bool {
        let key = irc_casefold(nick);
        self.nicks.contains_key(&key) || self.remote_nicks.contains_key(&key)
    }

    /// Rename a remote user's nick entry in the lookup map.
    pub fn rename_remote_nick(&self, old_nick: &str, new_nick: &str, numeric: ClientNumeric) {
        self.remote_nicks.remove(&irc_casefold(old_nick));
        self.remote_nicks.insert(irc_casefold(new_nick), numeric);
    }

    /// Get the first active server link (we only support one for now).
    pub fn get_link(&self) -> Option<Arc<ServerLink>> {
        self.links.iter().next().map(|e| Arc::clone(e.value()))
    }

    /// Send a raw P10 line to all server links. Used by forthcoming
    /// multi-link propagation paths; today we only have a single link
    /// and `get_link().send_line` covers the case.
    #[allow(dead_code)]
    pub async fn send_to_links(&self, line: &str) {
        for entry in self.links.iter() {
            entry.value().send_line(line.to_string()).await;
        }
    }

    /// Total user count (local + remote).
    pub fn total_user_count(&self) -> usize {
        self.clients.len() + self.remote_clients.len()
    }

    /// Count of users with the `+i` (invisible) mode across the network.
    pub async fn invisible_count(&self) -> usize {
        let mut n = 0;
        for entry in self.clients.iter() {
            if entry.value().read().await.modes.contains(&'i') {
                n += 1;
            }
        }
        for entry in self.remote_clients.iter() {
            if entry.value().read().await.modes.contains(&'i') {
                n += 1;
            }
        }
        n
    }

    /// Count of users with the `+o` (operator) mode across the network.
    pub async fn operator_count(&self) -> usize {
        let mut n = 0;
        for entry in self.clients.iter() {
            if entry.value().read().await.modes.contains(&'o') {
                n += 1;
            }
        }
        for entry in self.remote_clients.iter() {
            if entry.value().read().await.modes.contains(&'o') {
                n += 1;
            }
        }
        n
    }

    /// Total server count on the network, including this one.
    pub fn server_count(&self) -> usize {
        1 + self.remote_servers.len()
    }

    /// Mark a local client as logged in to `account`. Updates
    /// `Client.account`, sends RPL_LOGGEDIN to the client, broadcasts
    /// IRCv3 `account-notify` to local peers sharing a channel, and
    /// routes the P10 `AC` token across any S2S link. Symmetric with
    /// `logout_local`.
    pub async fn login_local(&self, id: ClientId, account: &crate::accounts::AccountInfo) {
        let (prefix, nick, channels, src) = {
            let Some(client_arc) = self.clients.get(&id) else {
                return;
            };
            let mut c = client_arc.write().await;
            c.account = Some(account.name.clone());
            (
                c.prefix(),
                c.nick.clone(),
                c.channels.iter().cloned().collect::<std::collections::HashSet<_>>(),
                crate::tags::SourceInfo::from_local(&c),
            )
        };

        // RPL_LOGGEDIN 900 <nick> <prefix> <account> :You are now logged in as <account>
        if let Some(client_arc) = self.clients.get(&id) {
            let c = client_arc.read().await;
            c.send(irc_proto::Message::with_source(
                &self.server_name,
                irc_proto::Command::Numeric(crate::numeric::RPL_LOGGEDIN),
                vec![
                    nick.clone(),
                    prefix.clone(),
                    account.name.clone(),
                    format!("You are now logged in as {}", account.name),
                ],
            ));
        }

        self.broadcast_account_change(id, &prefix, &account.name, &channels, &src).await;
        self.route_account_to_s2s(id, Some(&account.name), account.registered_ts).await;
    }

    /// Mark a local client as logged out. Symmetric with `login_local`.
    /// Not yet called — no /LOGOUT command or `AUTHENTICATE *` path
    /// wires this yet; ready for when one does.
    #[allow(dead_code)]
    pub async fn logout_local(&self, id: ClientId) {
        let (prefix, nick, channels, src, was_logged_in) = {
            let Some(client_arc) = self.clients.get(&id) else {
                return;
            };
            let mut c = client_arc.write().await;
            let was = c.account.is_some();
            c.account = None;
            (
                c.prefix(),
                c.nick.clone(),
                c.channels.iter().cloned().collect::<std::collections::HashSet<_>>(),
                crate::tags::SourceInfo::from_local(&c),
                was,
            )
        };

        if !was_logged_in {
            return;
        }

        if let Some(client_arc) = self.clients.get(&id) {
            let c = client_arc.read().await;
            c.send(irc_proto::Message::with_source(
                &self.server_name,
                irc_proto::Command::Numeric(crate::numeric::RPL_LOGGEDOUT),
                vec![
                    nick.clone(),
                    prefix.clone(),
                    "You are now logged out".to_string(),
                ],
            ));
        }

        self.broadcast_account_change(id, &prefix, "*", &channels, &src).await;
        self.route_account_to_s2s(id, None, chrono::Utc::now().timestamp() as u64).await;
    }

    /// IRCv3 account-notify fan-out. `account` is `"*"` on logout.
    async fn broadcast_account_change(
        &self,
        source_id: ClientId,
        source_prefix: &str,
        account: &str,
        source_channels: &std::collections::HashSet<String>,
        src: &crate::tags::SourceInfo,
    ) {
        let account_msg = irc_proto::Message::with_source(
            source_prefix,
            irc_proto::Command::Account,
            vec![account.to_string()],
        );
        let mut seen: std::collections::HashSet<ClientId> = std::collections::HashSet::new();
        for chan_name in source_channels {
            if let Some(channel) = self.get_channel(chan_name) {
                let chan = channel.read().await;
                for (&member_id, _) in &chan.members {
                    if member_id == source_id || !seen.insert(member_id) {
                        continue;
                    }
                    if let Some(member) = self.clients.get(&member_id) {
                        let m = member.read().await;
                        if m.has_cap(Capability::AccountNotify) {
                            m.send_from(account_msg.clone(), src);
                        }
                    }
                }
            }
        }
    }

    /// Emit the P10 `AC` (account) token across any S2S link so remote
    /// servers learn about the login/logout. Format matches
    /// nefarious2/ircd/m_account.c: for login we use the extended
    /// `AC <numeric> R <account> <ts>`; for logout we use `AC <numeric>
    /// U`. Accounts are carried as the source user's 5-char numeric.
    async fn route_account_to_s2s(
        &self,
        id: ClientId,
        account: Option<&str>,
        ts: u64,
    ) {
        let Some(link) = self.get_link() else {
            return;
        };
        let numeric = crate::s2s::routing::local_numeric(self, id);
        let line = match account {
            Some(name) => format!("{} AC {numeric} R {name} {ts}", self.numeric),
            None => format!("{} AC {numeric} U", self.numeric),
        };
        link.send_line(line).await;
    }

    /// Broadcast `CAP NEW`/`CAP DEL` notifications to every local
    /// `cap-notify` client. Called when the advertised set mutates
    /// (e.g. after a REHASH). `subcmd` is "NEW" or "DEL". Caps are
    /// sorted by name so the wire ordering is deterministic.
    /// Not yet called — REHASH is a follow-up; keep ready.
    #[allow(dead_code)]
    pub async fn broadcast_cap_notify(&self, subcmd: &str, caps: &[Capability]) {
        if caps.is_empty() {
            return;
        }
        // Render the CAP line contents once and reuse per recipient.
        let mut tokens: Vec<String> = caps
            .iter()
            .map(|c| match c.ls_value() {
                Some(v) => format!("{}={v}", c.name()),
                None => c.name().to_string(),
            })
            .collect();
        tokens.sort();
        let payload = tokens.join(" ");

        for entry in self.clients.iter() {
            let c = entry.value().read().await;
            if !c.has_cap(Capability::CapNotify) {
                continue;
            }
            let target = if c.nick.is_empty() { "*".to_string() } else { c.nick.clone() };
            c.send(irc_proto::Message::with_source(
                &self.server_name,
                irc_proto::Command::Cap,
                vec![target, subcmd.to_string(), payload.clone()],
            ));
        }
    }

    /// Generate ISUPPORT (005) tokens.
    pub fn isupport_tokens(&self) -> Vec<String> {
        // Values sourced from Features block where present; defaults
        // below match nefarious2 ircd_features.c so a bare config
        // produces the same ISUPPORT advertisement the C build does.
        let nicklen = self.config.nicklen();
        let channellen = self.config.channellen();
        let max_bans = self.config.max_bans();
        let max_siles = self.config.max_siles();
        let max_watchs = self.config.max_watchs();
        let max_channels = self.config.max_channels_per_user();
        vec![
            "CASEMAPPING=rfc1459".to_string(),
            format!("CHANLIMIT=#:{max_channels}"),
            "CHANMODES=b,k,l,imnpst".to_string(),
            format!("CHANNELLEN={channellen}"),
            format!("MAXBANS={max_bans}"),
            format!("MAXCHANNELS={max_channels}"),
            format!("MAXLIST=b:{max_bans}"),
            format!("NETWORK={}", self.config.network()),
            format!("NICKLEN={nicklen}"),
            "PREFIX=(ov)@+".to_string(),
            format!("SILENCE={max_siles}"),
            "TOPICLEN=390".to_string(),
            format!("WATCH={max_watchs}"),
            "MODES=6".to_string(),
        ]
    }
}

/// Split `nick!user@host` into (`user`, `host`) borrowed slices.
/// Returns `None` when either delimiter is missing. Used by the
/// WATCH numeric emitters which want the user and host separately.
fn split_user_host(prefix: &str) -> Option<(&str, &str)> {
    let bang = prefix.find('!')?;
    let at = prefix[bang + 1..].find('@')?;
    let user = &prefix[bang + 1..bang + 1 + at];
    let host = &prefix[bang + 1 + at + 1..];
    Some((user, host))
}
