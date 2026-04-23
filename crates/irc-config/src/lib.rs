pub mod parser;

use std::path::Path;
use std::time::Duration;

use parser::{Block, TopLevel, parse_config};

/// Fully resolved server configuration.
#[derive(Debug, Clone)]
pub struct Config {
    pub general: GeneralConfig,
    pub admin: AdminConfig,
    pub ports: Vec<PortConfig>,
    pub classes: Vec<ClassConfig>,
    pub clients: Vec<ClientConfig>,
    pub operators: Vec<OperatorConfig>,
    pub connects: Vec<ConnectConfig>,
    pub features: Vec<(String, String)>,
}

#[derive(Debug, Clone)]
pub struct GeneralConfig {
    pub name: String,
    pub description: String,
    pub numeric: u16,
    pub vhost: Option<String>,
    /// Suffix appended to an authenticated user's account to form
    /// their visible cloaked host when +x is set — i.e. `<account>.<suffix>`.
    /// Matches nefarious2 FEAT_HIDDEN_HOST (used when
    /// FEAT_HOST_HIDING_STYLE is 1 or 3). When `None`, fall back to
    /// the wire cloakhost carried in the P10 NICK intro. Must match
    /// the peer network's setting for display consistency.
    pub hidden_host_suffix: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct AdminConfig {
    pub location: Vec<String>,
    pub contact: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortConfig {
    pub port: u16,
    pub ssl: bool,
    pub server: bool,
    pub websocket: WebSocketMode,
    pub vhost: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WebSocketMode {
    No,
    Yes,
    Auto,
}

#[derive(Debug, Clone)]
pub struct ClassConfig {
    pub name: String,
    pub pingfreq: Duration,
    pub connectfreq: Duration,
    pub maxlinks: u32,
    pub sendq: u64,
    pub bouncer: bool,
    pub require_sasl: bool,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub class: String,
    pub ip: String,
    pub host: Option<String>,
    pub password: Option<String>,
    pub maxlinks: u32,
    pub port: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct OperatorConfig {
    pub name: String,
    pub host: String,
    pub password: String,
    pub class: String,
    pub local: bool,
    /// Whitespace-separated priv names (e.g. "KILL REHASH OPMODE").
    /// Names match nefarious2 `privtab`. When absent, a sensible
    /// default set is applied at /OPER time (see
    /// `handlers::query::handle_oper`).
    pub privs: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ConnectConfig {
    pub name: String,
    pub host: String,
    pub password: String,
    pub port: u16,
    pub class: String,
    pub hub: bool,
    pub autoconnect: bool,
    pub ssl: bool,
}

impl Config {
    /// Look up a Features block entry by key (case-insensitive), as
    /// nefarious2 treats feature names case-insensitively. Returns
    /// the raw value string if present.
    pub fn feature(&self, key: &str) -> Option<&str> {
        self.features
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Convenience: the NETWORK feature value, falling back to the
    /// server name when unset. Used for RPL_WELCOME and ISUPPORT
    /// NETWORK= so the user sees the network brand rather than the
    /// individual server's hostname.
    pub fn network(&self) -> &str {
        self.feature("NETWORK").unwrap_or(&self.general.name)
    }

    /// `HIS_SERVERNAME` — the pseudo-server string shown to non-opers
    /// in WHOIS 312, LINKS, and similar paths that would otherwise
    /// reveal the user's home server hostname. `None` means "don't
    /// hide" and callers should use the real server name.
    ///
    /// Common deployments set this to the network hostname (e.g.
    /// `*.AfterNET.org`) so cross-network users see consistent output
    /// regardless of which edge server they're actually on.
    pub fn his_servername(&self) -> Option<&str> {
        self.feature("HIS_SERVERNAME")
    }

    /// `HIS_SERVERINFO` — the pseudo server description shown
    /// alongside `HIS_SERVERNAME` in WHOIS 312 / LINKS when hiding
    /// is in effect.
    pub fn his_serverinfo(&self) -> Option<&str> {
        self.feature("HIS_SERVERINFO")
    }

    /// Boolean feature helper — parses common truthy/falsy forms
    /// (`yes`/`no`, `true`/`false`, `on`/`off`, `1`/`0`). Returns the
    /// supplied default when the key isn't present or isn't parseable.
    pub fn feature_bool(&self, key: &str, default: bool) -> bool {
        match self.feature(key) {
            Some(v) => match v.to_ascii_lowercase().as_str() {
                "yes" | "true" | "on" | "1" => true,
                "no" | "false" | "off" | "0" => false,
                _ => default,
            },
            None => default,
        }
    }

    /// `HIS_WHOIS_IDLETIME` — when true, suppress the 317
    /// RPL_WHOISIDLE line for non-opers querying a stranger.
    /// Self-WHOIS and oper WHOIS still see the idle field.
    /// Defaults to true in nefarious2 (ircd_features.c).
    pub fn his_whois_idletime(&self) -> bool {
        self.feature_bool("HIS_WHOIS_IDLETIME", true)
    }

    /// `MAXWATCHS` — per-client cap on the WATCH/MONITOR list size.
    /// Defaults to 128, matching nefarious2's F_I(MAXWATCHS, …, 128).
    /// Invalid values in the config silently fall back to the default.
    pub fn max_watchs(&self) -> u32 {
        self.feature("MAXWATCHS")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(128)
    }

    /// `MAXSILES` — per-client cap on the SILENCE list size. Defaults
    /// to 25, matching nefarious2's F_I(MAXSILES, …, 25).
    pub fn max_siles(&self) -> u32 {
        self.feature("MAXSILES")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(25)
    }

    /// `NICKLEN` — maximum nickname length, exposed via ISUPPORT.
    /// Defaults to 15 to match nefarious2's F_I(NICKLEN, …, 15).
    pub fn nicklen(&self) -> u32 {
        self.feature("NICKLEN")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(15)
    }

    /// `CHANNELLEN` — maximum channel name length. Defaults to 200.
    pub fn channellen(&self) -> u32 {
        self.feature("CHANNELLEN")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(200)
    }

    /// `MAXBANS` — per-channel ban list cap; ISUPPORT `MAXBANS` and
    /// one half of `MAXLIST`. Defaults to 50.
    pub fn max_bans(&self) -> u32 {
        self.feature("MAXBANS")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(50)
    }

    /// `MAXCHANNELSPERUSER` — per-client cap on joined channels;
    /// ISUPPORT `MAXCHANNELS`. Defaults to 20.
    pub fn max_channels_per_user(&self) -> u32 {
        self.feature("MAXCHANNELSPERUSER")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(20)
    }

    /// Load a configuration from a file path, resolving includes.
    pub fn from_file(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;

        let base_dir = path.parent().unwrap_or(Path::new("."));
        Self::from_str_with_includes(&content, base_dir)
    }

    /// Parse config from a string, resolving includes relative to `base_dir`.
    pub fn from_str_with_includes(input: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let items = parse_config(input).map_err(ConfigError::Parse)?;

        let mut all_blocks = Vec::new();

        for item in items {
            match item {
                TopLevel::Block(b) => all_blocks.push(b),
                TopLevel::Include(path) => {
                    let full_path = base_dir.join(&path);
                    match std::fs::read_to_string(&full_path) {
                        Ok(content) => {
                            let _include_dir = full_path.parent().unwrap_or(base_dir);
                            let sub_items = parse_config(&content)
                                .map_err(|e| ConfigError::Parse(format!("in {path}: {e}")))?;
                            for sub in sub_items {
                                if let TopLevel::Block(b) = sub {
                                    all_blocks.push(b);
                                }
                                // Nested includes could be handled recursively, skip for now
                            }
                        }
                        Err(e) => {
                            tracing::warn!("could not read include file {}: {}", path, e);
                        }
                    }
                }
            }
        }

        Self::from_blocks(&all_blocks)
    }

    /// Build config from parsed blocks.
    fn from_blocks(blocks: &[Block]) -> Result<Self, ConfigError> {
        let mut general = None;
        let mut admin = AdminConfig::default();
        let mut ports = Vec::new();
        let mut classes = Vec::new();
        let mut clients = Vec::new();
        let mut operators = Vec::new();
        let mut connects = Vec::new();
        let mut features = Vec::new();

        for block in blocks {
            match block.kind.as_str() {
                "General" => {
                    general = Some(GeneralConfig {
                        name: block
                            .get_str("name")
                            .ok_or_else(|| ConfigError::Missing("General.name".into()))?
                            .to_string(),
                        description: block
                            .get_str("description")
                            .unwrap_or("nefarious-rs")
                            .to_string(),
                        numeric: block
                            .get_i64("numeric")
                            .and_then(|n| u16::try_from(n).ok())
                            .ok_or_else(|| ConfigError::Missing("General.numeric".into()))?,
                        vhost: block.get_str("vhost").map(|s| s.to_string()),
                        hidden_host_suffix: block
                            .get_str("hiddenhost")
                            .or_else(|| block.get_str("hidden_host"))
                            .map(|s| s.to_string()),
                    });
                }

                "Admin" => {
                    for v in block.get_all("Location") {
                        if let Some(s) = v.as_str() {
                            admin.location.push(s.to_string());
                        }
                    }
                    admin.contact = block.get_str("Contact").map(|s| s.to_string());
                }

                "Port" => {
                    let port = block
                        .get("port")
                        .and_then(|v| v.as_u16())
                        .ok_or_else(|| ConfigError::Missing("Port.port".into()))?;

                    let ws_mode = match block.get_str("websocket") {
                        Some("auto") => WebSocketMode::Auto,
                        _ if block.get_bool("websocket") == Some(true) => WebSocketMode::Yes,
                        _ => WebSocketMode::No,
                    };

                    ports.push(PortConfig {
                        port,
                        ssl: block.get_bool("ssl").unwrap_or(false),
                        server: block.get_bool("server").unwrap_or(false),
                        websocket: ws_mode,
                        vhost: block.get_str("vhost").map(|s| s.to_string()),
                    });
                }

                "Class" => {
                    classes.push(ClassConfig {
                        name: block
                            .get_str("name")
                            .ok_or_else(|| ConfigError::Missing("Class.name".into()))?
                            .to_string(),
                        pingfreq: block
                            .get("pingfreq")
                            .and_then(|v| v.as_duration())
                            .unwrap_or(Duration::from_secs(90)),
                        connectfreq: block
                            .get("connectfreq")
                            .and_then(|v| v.as_duration())
                            .unwrap_or(Duration::from_secs(0)),
                        maxlinks: block.get_i64("maxlinks").unwrap_or(0) as u32,
                        sendq: block.get_i64("sendq").unwrap_or(100000) as u64,
                        bouncer: block.get_bool("bouncer").unwrap_or(false),
                        require_sasl: block.get_bool("require_sasl").unwrap_or(false),
                    });
                }

                "Client" => {
                    clients.push(ClientConfig {
                        class: block
                            .get_str("class")
                            .unwrap_or("default")
                            .to_string(),
                        ip: block.get_str("ip").unwrap_or("*").to_string(),
                        host: block.get_str("host").map(|s| s.to_string()),
                        password: block.get_str("password").map(|s| s.to_string()),
                        maxlinks: block.get_i64("maxlinks").unwrap_or(0) as u32,
                        port: block.get("port").and_then(|v| v.as_u16()),
                    });
                }

                "Operator" => {
                    operators.push(OperatorConfig {
                        name: block
                            .get_str("name")
                            .ok_or_else(|| ConfigError::Missing("Operator.name".into()))?
                            .to_string(),
                        host: block.get_str("host").unwrap_or("*@*").to_string(),
                        password: block
                            .get_str("password")
                            .ok_or_else(|| ConfigError::Missing("Operator.password".into()))?
                            .to_string(),
                        class: block.get_str("class").unwrap_or("Opers").to_string(),
                        local: block.get_bool("local").unwrap_or(true),
                        privs: block.get_str("privs").map(|s| s.to_string()),
                    });
                }

                "Connect" => {
                    connects.push(ConnectConfig {
                        name: block
                            .get_str("name")
                            .ok_or_else(|| ConfigError::Missing("Connect.name".into()))?
                            .to_string(),
                        host: block
                            .get_str("host")
                            .ok_or_else(|| ConfigError::Missing("Connect.host".into()))?
                            .to_string(),
                        password: block
                            .get_str("password")
                            .ok_or_else(|| ConfigError::Missing("Connect.password".into()))?
                            .to_string(),
                        port: block
                            .get("port")
                            .and_then(|v| v.as_u16())
                            .ok_or_else(|| ConfigError::Missing("Connect.port".into()))?,
                        class: block.get_str("class").unwrap_or("Server").to_string(),
                        hub: block.has_flag("hub"),
                        autoconnect: block.get_bool("autoconnect").unwrap_or(false),
                        ssl: block.get_bool("ssl").unwrap_or(false),
                    });
                }

                "Features" => {
                    for entry in &block.entries {
                        if let parser::Entry::KeyValue(k, v) = entry {
                            let val_str = match v {
                                parser::Value::String(s) => s.clone(),
                                parser::Value::Integer(n) => n.to_string(),
                                parser::Value::Boolean(b) => {
                                    if *b { "TRUE" } else { "FALSE" }.to_string()
                                }
                                parser::Value::Duration(d) => d.as_secs().to_string(),
                            };
                            features.push((k.clone(), val_str));
                        }
                    }
                }

                other => {
                    tracing::debug!("ignoring unknown config block: {other}");
                }
            }
        }

        let general =
            general.ok_or_else(|| ConfigError::Missing("General block is required".into()))?;

        Ok(Config {
            general,
            admin,
            ports,
            classes,
            clients,
            operators,
            connects,
            features,
        })
    }

    /// Get client-facing (non-server) port configs.
    pub fn client_ports(&self) -> impl Iterator<Item = &PortConfig> {
        self.ports.iter().filter(|p| !p.server)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("I/O error: {0}")]
    Io(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("missing required config: {0}")]
    Missing(String),
}
