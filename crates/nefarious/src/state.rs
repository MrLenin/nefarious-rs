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
use crate::s2s::types::{RemoteClient, RemoteServer, ServerLink};

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
}

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
            config: Arc::new(config),
            motd: vec![
                "Welcome to nefarious-rs".to_string(),
                "A Rust implementation of Nefarious IRCd".to_string(),
            ],
            dns_resolver,
            advertised_caps: default_advertised_caps(),
            account_store: crate::accounts::empty_in_memory(),
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

        // Remove from nick map
        let nick = {
            if let Some(client) = self.clients.get(&id) {
                let c = client.read().await;
                irc_casefold(&c.nick)
            } else {
                return;
            }
        };
        self.nicks.remove_if(&nick, |_, v| *v == id);

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

    /// Remove a remote client (QUIT, KILL, SQUIT).
    pub async fn remove_remote_client(&self, numeric: ClientNumeric) {
        let nick = {
            if let Some(client) = self.remote_clients.get(&numeric) {
                let c = client.read().await;
                irc_casefold(&c.nick)
            } else {
                return;
            }
        };
        self.remote_nicks.remove(&nick);

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

    /// Send a raw P10 line to all server links.
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
        vec![
            "CASEMAPPING=rfc1459".to_string(),
            "CHANLIMIT=#:100".to_string(),
            "CHANMODES=b,k,l,imnpst".to_string(),
            "CHANNELLEN=200".to_string(),
            format!("NETWORK={}", self.server_name),
            "NICKLEN=30".to_string(),
            "PREFIX=(ov)@+".to_string(),
            "TOPICLEN=390".to_string(),
            "MODES=6".to_string(),
        ]
    }
}
