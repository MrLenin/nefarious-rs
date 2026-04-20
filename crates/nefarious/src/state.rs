use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::RwLock;

use irc_config::Config;
use p10_proto::{ClientNumeric, ServerNumeric};

use crate::channel::Channel;
use crate::client::{Client, ClientId};
use crate::s2s::types::{RemoteClient, RemoteServer, ServerLink};

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
}

impl ServerState {
    pub fn new(config: Config) -> Self {
        let now = chrono::Utc::now();
        Self {
            server_name: config.general.name.clone(),
            server_description: config.general.description.clone(),
            created_at: now,
            start_timestamp: now.timestamp() as u64,
            version: format!("nefarious-rs-{}", env!("CARGO_PKG_VERSION")),
            clients: DashMap::new(),
            nicks: DashMap::new(),
            channels: DashMap::new(),
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
        }
    }

    /// Register a client (after NICK+USER complete).
    pub async fn register_client(&self, client: Arc<RwLock<Client>>, nick: &str) {
        let id = {
            let c = client.read().await;
            c.id
        };
        self.nicks.insert(nick.to_ascii_lowercase(), id);
        self.clients.insert(id, client);
    }

    /// Remove a client entirely.
    pub async fn remove_client(&self, id: ClientId) {
        // Remove from nick map
        let nick = {
            if let Some(client) = self.clients.get(&id) {
                let c = client.read().await;
                c.nick.to_ascii_lowercase()
            } else {
                return;
            }
        };
        self.nicks.remove(&nick);

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

    /// Look up a client by nick (case-insensitive).
    pub fn find_client_by_nick(&self, nick: &str) -> Option<Arc<RwLock<Client>>> {
        let id = self.nicks.get(&nick.to_ascii_lowercase())?;
        let client = self.clients.get(&*id)?;
        Some(Arc::clone(client.value()))
    }

    /// Update the nick mapping when a client changes nick.
    pub fn change_nick(&self, id: ClientId, old_nick: &str, new_nick: &str) {
        self.nicks.remove(&old_nick.to_ascii_lowercase());
        self.nicks.insert(new_nick.to_ascii_lowercase(), id);
    }

    /// Get or create a channel.
    pub fn get_or_create_channel(&self, name: &str) -> Arc<RwLock<Channel>> {
        let key = name.to_ascii_lowercase();
        self.channels
            .entry(key)
            .or_insert_with(|| Arc::new(RwLock::new(Channel::new(name.to_string()))))
            .value()
            .clone()
    }

    /// Get a channel if it exists.
    pub fn get_channel(&self, name: &str) -> Option<Arc<RwLock<Channel>>> {
        self.channels
            .get(&name.to_ascii_lowercase())
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
        self.remote_nicks.insert(nick.to_ascii_lowercase(), numeric);
        self.remote_clients.insert(numeric, client);
    }

    /// Remove a remote client (QUIT, KILL, SQUIT).
    pub async fn remove_remote_client(&self, numeric: ClientNumeric) {
        let nick = {
            if let Some(client) = self.remote_clients.get(&numeric) {
                let c = client.read().await;
                c.nick.to_ascii_lowercase()
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
            if chan.is_empty() && chan.remote_members.is_empty() {
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

    /// Find a remote client by nick (case-insensitive).
    pub fn find_remote_by_nick(&self, nick: &str) -> Option<Arc<RwLock<RemoteClient>>> {
        let numeric = self.remote_nicks.get(&nick.to_ascii_lowercase())?;
        let client = self.remote_clients.get(&*numeric)?;
        Some(Arc::clone(client.value()))
    }

    /// Check if a nick is in use by either a local or remote user.
    pub fn nick_in_use(&self, nick: &str) -> bool {
        let lower = nick.to_ascii_lowercase();
        self.nicks.contains_key(&lower) || self.remote_nicks.contains_key(&lower)
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

    /// Generate ISUPPORT (005) tokens.
    pub fn isupport_tokens(&self) -> Vec<String> {
        vec![
            "CASEMAPPING=ascii".to_string(),
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
