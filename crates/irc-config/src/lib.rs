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
    pub kills: Vec<KillConfig>,
    pub webirc: Vec<WebIrcConfig>,
    pub dnsbl: Vec<DnsBlConfig>,
    pub features: Vec<(String, String)>,
}

/// A DNSBL (DNS-based blackhole list) zone to query at connect
/// time. Mirrors nefarious2's `DNSBL {}` config block and the
/// DNSBL_ACT_* enum from include/dnsbl.h.
///
/// In the C grammar the canonical keys are `name`, `host`,
/// `bitmask`, `action`, `mark`, `score`. The parser accepts
/// `domain`/`reply`/`reason` as legacy aliases for backwards
/// compatibility with our older single-zone schema.
#[derive(Debug, Clone)]
pub struct DnsBlConfig {
    /// Zone to query, e.g. `zen.spamhaus.org`. The client IP is
    /// reversed and prepended per RFC 5782 — `1.2.3.4` becomes a
    /// query for `4.3.2.1.zen.spamhaus.org`. Sourced from the
    /// `name` (or legacy `domain`) key.
    pub name: String,
    /// Raw `host` index string as written in the conf, retained for
    /// `/STATS D` display. The compiled match value is in `bitmask`.
    pub host: Option<String>,
    /// Bitmask-of-indexes match for the returned A-record's last
    /// octet. The C parser interprets `host = "2,3,4,5,6,7,9"` as
    /// `(1<<2)|(1<<3)|...|(1<<9)`; a reply of `127.0.0.4` matches
    /// when `(1u32 << 4) & bitmask != 0`. `0xFFFFFFFF` means "any
    /// reply matches" — used when neither `host` nor `bitmask` was
    /// specified, mirroring dnsbl.c's default.
    pub bitmask: u32,
    /// What to do when the client's IP is listed.
    pub action: DnsBlAction,
    /// Oper-visible mark / refusal reason. Sourced from `mark` (or
    /// legacy `reason`). Shown to the client on `Block`/`BlockAll`
    /// and to opers via `/CHECK` / `/WHOIS` on `Mark`/`BlockAnon`.
    pub mark: String,
    /// Reputation score the C version aggregates per client when
    /// multiple zones list the same IP. Stored verbatim; the
    /// scoring policy is not yet wired in nefarious-rs.
    pub score: i32,
}

/// Action to take when a DNSBL reports a match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsBlAction {
    /// Refuse the connection outright (anon and authed alike).
    /// Maps to nefarious2 DNSBL_ACT_BLOCK.
    Block,
    /// Refuse every client unconditionally — even SASL-authed
    /// users are kicked. Stronger than `Block` only insofar as
    /// future per-block exemptions wouldn't apply. Maps to
    /// DNSBL_ACT_BLOCK_ALL.
    BlockAll,
    /// Refuse only non-authenticated clients; authed users bypass
    /// the block but still get tagged with the mark for opers.
    BlockAnon,
    /// Tag the client (stored on Client state) but let them in.
    /// Opers can see the mark via /WHOIS / /CHECK.
    Mark,
    /// Exempt the IP from other DNSBL checks in this list.
    Whitelist,
}

/// Trusted WEBIRC gateway entry — lets a known webchat gateway
/// pass through the real client's IP/host via the WEBIRC command.
/// Mirrors nefarious2 ircd.conf WebIRC block.
#[derive(Debug, Clone)]
pub struct WebIrcConfig {
    /// Password the gateway must present on the WEBIRC line. May
    /// be plaintext or a bcrypt `$2a$/$2b$/$2y$` hash — the
    /// verifier auto-detects via the prefix.
    pub password: String,
    /// Optional host glob the gateway's actual source IP must
    /// match before the password is even consulted, per nefarious2
    /// m_webirc.c's client.host check. `None` means any host.
    pub host: Option<String>,
    /// Optional description shown in oper notices.
    pub description: Option<String>,
}

/// A local connection ban sourced from a `Kill { ... }` config
/// block. Static (tied to the config file) rather than the dynamic
/// GLINE/SHUN/ZLINE path — reloaded on /REHASH.
#[derive(Debug, Clone)]
pub struct KillConfig {
    /// `user@host` glob. Supports `*` and `?` wildcards.
    pub host: String,
    /// Optional IP/CIDR; when set, matches on the peer's IP as well
    /// as the resolved host. Mirrors nefarious2 ircd.conf Kill block.
    pub ip: Option<String>,
    /// Reason text shown to the refused client.
    pub reason: String,
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

    /// `HIS_MAP` — hide `/MAP` output (other than the home server)
    /// from non-opers. Defaults to true.
    pub fn his_map(&self) -> bool {
        self.feature_bool("HIS_MAP", true)
    }

    /// `HIS_LINKS` — same idea as HIS_MAP but for the `/LINKS`
    /// surface. Defaults to true.
    pub fn his_links(&self) -> bool {
        self.feature_bool("HIS_LINKS", true)
    }

    /// `HIS_WHO_SERVERNAME` — hide the real server column in WHO
    /// replies for non-opers (substitute HIS_SERVERNAME). Default true.
    pub fn his_who_servername(&self) -> bool {
        self.feature_bool("HIS_WHO_SERVERNAME", true)
    }

    /// `HIS_WHO_HOPCOUNT` — report 0 as the hop count in WHO replies
    /// for non-opers rather than the real value. Default true.
    pub fn his_who_hopcount(&self) -> bool {
        self.feature_bool("HIS_WHO_HOPCOUNT", true)
    }

    /// `IPCHECK_CLONE_LIMIT` — maximum connections a single IP may
    /// have in-flight within `IPCHECK_CLONE_PERIOD` seconds.
    /// Defaults to 4 (matches nefarious2 ipcheck.c).
    pub fn ipcheck_clone_limit(&self) -> u32 {
        self.feature("IPCHECK_CLONE_LIMIT")
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(4)
    }

    /// `IPCHECK_CLONE_PERIOD` — rolling window in seconds for
    /// IPCHECK_CLONE_LIMIT enforcement. Defaults to 40s.
    pub fn ipcheck_clone_period(&self) -> u64 {
        self.feature("IPCHECK_CLONE_PERIOD")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(40)
    }

    /// `MPATH` — filesystem path to the MOTD file. When unset the
    /// server's built-in banner is used. /REHASH re-reads this
    /// file into state.motd without restarting the server.
    pub fn motd_path(&self) -> Option<&str> {
        self.feature("MPATH")
    }

    /// `MMDB_FILE` — filesystem path to a MaxMind GeoLite2 / GeoIP2
    /// Country MMDB database. When set, clients get tagged with
    /// country_code / country_name / continent_code at connect.
    /// When unset, GeoIP columns read "--" / "Unknown".
    pub fn mmdb_file(&self) -> Option<&str> {
        self.feature("MMDB_FILE")
    }

    /// `DNSBL_TIMEOUT` — per-zone DNS query timeout in seconds. The
    /// hard cap on connect-path DNSBL latency is roughly this value,
    /// since all configured zones run concurrently. Defaults to 5s
    /// matching nefarious2 ircd_features.c.
    pub fn dnsbl_timeout(&self) -> u64 {
        self.feature("DNSBL_TIMEOUT")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5)
    }

    /// `DNSBL_CACHETIME` — how long (seconds) a per-IP DNSBL result
    /// is cached so subsequent connects from the same address skip
    /// the DNS round trip. Defaults to 6h, matching nefarious2.
    pub fn dnsbl_cachetime(&self) -> u64 {
        self.feature("DNSBL_CACHETIME")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(21600)
    }

    /// `GIT_CONFIG_PATH` — working-tree path of a git checkout
    /// containing the config file. When set, a background task
    /// runs `git pull --ff-only` every `GIT_SYNC_INTERVAL`
    /// seconds; if the HEAD moved, it triggers a reload_config
    /// automatically so ops can roll a network-wide config change
    /// by pushing to the repo.
    pub fn git_config_path(&self) -> Option<&str> {
        self.feature("GIT_CONFIG_PATH")
    }

    /// `GIT_SYNC_INTERVAL` — seconds between automatic git pulls.
    /// Defaults to 300 (5 minutes). Set to 0 to disable the
    /// background loop while keeping /GITSYNC available for
    /// manual pulls.
    pub fn git_sync_interval(&self) -> u64 {
        self.feature("GIT_SYNC_INTERVAL")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(300)
    }

    /// `GITSYNC_SSH_KEY` — path to a PEM/OpenSSH key for libssh2
    /// to authenticate against the git remote. When unset, gitsync
    /// falls back to the server's TLS certfile (which contains a
    /// usable private key in PEM form); this is how nefarious2
    /// avoids provisioning a separate SSH key on each host.
    pub fn gitsync_ssh_key(&self) -> Option<&str> {
        self.feature("GITSYNC_SSH_KEY")
    }

    /// `GITSYNC_HOST_FINGERPRINT` — pinned SSH host key fingerprint
    /// (hex-with-colons form, e.g. `aa:bb:cc:...`). When set, the
    /// host must present exactly this fingerprint or the pull
    /// fails. When unset, TOFU behaviour applies: the first pull
    /// records the remote's fingerprint, later pulls verify it.
    pub fn gitsync_host_fingerprint(&self) -> Option<&str> {
        self.feature("GITSYNC_HOST_FINGERPRINT")
    }

    /// `GITSYNC_CERT_PATH` — filename within the synced repo's
    /// working tree that carries the server's TLS certificate
    /// (PEM, may include the key). When set, a successful pull
    /// that touches this file triggers an atomic install to
    /// `GITSYNC_CERT_FILE` (or the server's running certfile)
    /// and a live SSL acceptor reload. Lets an operator rotate
    /// certs across the whole network with one `git push`.
    pub fn gitsync_cert_path(&self) -> Option<&str> {
        self.feature("GITSYNC_CERT_PATH")
    }

    /// `GITSYNC_CERT_FILE` — filesystem destination where the
    /// synced cert gets written. Defaults to `SSL_CERTFILE`
    /// (since that's the path the TLS acceptor is already
    /// reading) but can be overridden for setups where the
    /// live cert is a symlink or owned by a different process.
    pub fn gitsync_cert_file(&self) -> Option<&str> {
        self.feature("GITSYNC_CERT_FILE")
            .or_else(|| self.feature("SSL_CERTFILE"))
    }

    /// `SSL_CERTFILE` — path to the live TLS certificate. Used by
    /// the acceptor and as the default destination for
    /// `GITSYNC_CERT_PATH`-driven installs. When absent we fall
    /// back to the process' `SSL_CERT` environment variable
    /// (which is how main.rs wires things up today).
    pub fn ssl_certfile(&self) -> Option<&str> {
        self.feature("SSL_CERTFILE")
    }

    /// `SSL_KEYFILE` — path to the live TLS key. Used by the
    /// acceptor alongside `SSL_CERTFILE`.
    pub fn ssl_keyfile(&self) -> Option<&str> {
        self.feature("SSL_KEYFILE")
    }

    /// `HOST_HIDING_STYLE` — which cloak strategy applies on +x.
    /// 0 = no cloak, 1 = account-based only, 2 = crypto cloak
    /// only, 3 = both (account wins when logged in, crypto
    /// otherwise). Default 1 (matches ircd_features.c).
    pub fn host_hiding_style(&self) -> u8 {
        self.feature("HOST_HIDING_STYLE")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(1)
    }

    /// `HOST_HIDING_KEY1/2/3` — the three salts used by the
    /// crypto cloak. All three must match across every server on
    /// the network, otherwise cloaked hosts desync and bans miss.
    /// Returns `("","","")` when unset; with empty keys the cloak
    /// still produces a deterministic output, just a less-salted
    /// one — operators are expected to set these.
    pub fn host_hiding_keys(&self) -> [&str; 3] {
        [
            self.feature("HOST_HIDING_KEY1").unwrap_or(""),
            self.feature("HOST_HIDING_KEY2").unwrap_or(""),
            self.feature("HOST_HIDING_KEY3").unwrap_or(""),
        ]
    }

    /// `HOST_HIDING_PREFIX` — leading token on a cloaked resolved
    /// host (`<prefix>-<alpha>.<rem>`). Defaults to "nefarious".
    pub fn host_hiding_prefix(&self) -> &str {
        self.feature("HOST_HIDING_PREFIX").unwrap_or("nefarious")
    }

    /// `HOST_HIDING_COMPONENTS` — how many leading labels to drop
    /// when cloaking a resolved host. 1 keeps the TLD, 2 keeps
    /// TLD+second-level, etc. Default 1.
    pub fn host_hiding_components(&self) -> u8 {
        self.feature("HOST_HIDING_COMPONENTS")
            .and_then(|v| v.parse::<u8>().ok())
            .unwrap_or(1)
    }

    /// `CONNEXIT_NOTICES` — when true, send server notices for each
    /// connect/exit/nickchg to opers with the `+s` umode. Defaults
    /// to false in nefarious2 (operators opt in explicitly).
    pub fn connexit_notices(&self) -> bool {
        self.feature_bool("CONNEXIT_NOTICES", false)
    }

    /// `SILENCE_CHANMSGS` — when true, SILENCE also filters channel
    /// messages (not just private ones) and the server bursts each
    /// user's silence list to peers so remote filtering can happen.
    /// Defaults to false.
    pub fn silence_chanmsgs(&self) -> bool {
        self.feature_bool("SILENCE_CHANMSGS", false)
    }

    /// `NICKDELAY` — minimum seconds between local nick changes
    /// from a single client. Defaults to 30 (matches ircd_features.c
    /// F_I(NICKDELAY, 0, 30, 0)). Set to 0 to disable.
    pub fn nick_delay(&self) -> u64 {
        self.feature("NICKDELAY")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(30)
    }

    /// `PINGFREQ` — seconds of idle before the server sends a PING
    /// to a client to verify it's still alive. Defaults to 120.
    pub fn ping_freq(&self) -> u64 {
        self.feature("PINGFREQ")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(120)
    }

    /// `CONNECTTIMEOUT` — additional grace seconds after PING before
    /// the connection is killed for unresponsiveness. Effective
    /// max-idle before disconnect is `PINGFREQ + CONNECTTIMEOUT`.
    /// Defaults to 60 (so default total is 180s).
    pub fn connect_timeout(&self) -> u64 {
        self.feature("CONNECTTIMEOUT")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(60)
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

    /// Parse config from a string, resolving includes relative to
    /// `base_dir`. Nested includes are handled recursively with a
    /// seen-set that prevents include cycles from looping forever.
    pub fn from_str_with_includes(input: &str, base_dir: &Path) -> Result<Self, ConfigError> {
        let items = parse_config(input).map_err(ConfigError::Parse)?;
        let mut all_blocks = Vec::new();
        let mut seen: std::collections::HashSet<std::path::PathBuf> =
            std::collections::HashSet::new();
        collect_blocks(items, base_dir, &mut all_blocks, &mut seen)?;
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
        let mut kills = Vec::new();
        let mut webirc = Vec::new();
        let mut dnsbl = Vec::new();
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

                "DnsBL" | "DNSBL" => {
                    // Accept the canonical nefarious2 keys (`name`,
                    // `host`, `bitmask`, `mark`) and our older
                    // (`domain`, `reply`, `reason`) aliases. The
                    // testnet ircd.conf uses the canonical form;
                    // existing nefarious-rs configs use the aliases.
                    let name = match block.get_str("name").or_else(|| block.get_str("domain")) {
                        Some(d) => d.to_string(),
                        None => {
                            tracing::warn!("DNSBL block missing name; ignoring");
                            continue;
                        }
                    };
                    let action_str = block.get_str("action").unwrap_or("mark");
                    let action = match action_str.to_ascii_lowercase().as_str() {
                        "block" => DnsBlAction::Block,
                        "block_all" | "blockall" => DnsBlAction::BlockAll,
                        "block_anon" | "blockanon" => DnsBlAction::BlockAnon,
                        "mark" => DnsBlAction::Mark,
                        "whitelist" => DnsBlAction::Whitelist,
                        other => {
                            tracing::warn!(
                                "DNSBL {name}: unknown action '{other}'; defaulting to mark"
                            );
                            DnsBlAction::Mark
                        }
                    };
                    // `host` is a comma-separated list of accepted
                    // last-octet values (`"2,3,4,5,6,7,9"`); each
                    // becomes a set bit in the index bitmask.
                    // `bitmask` is the explicit form (a single
                    // integer literal). When neither is present we
                    // match any reply, matching dnsbl.c's
                    // `0xFFFFFFFF` default.
                    let host_str = block.get_str("host").map(|s| s.to_string());
                    let host_mask = host_str.as_deref().map(parse_dnsbl_index);
                    let explicit_bitmask = block
                        .get_str("bitmask")
                        .or_else(|| block.get_str("reply"))
                        .and_then(|v| {
                            let s = v.trim();
                            if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                                u32::from_str_radix(hex, 16).ok()
                            } else {
                                s.parse::<u32>().ok()
                            }
                        });
                    let bitmask = host_mask
                        .or(explicit_bitmask)
                        .unwrap_or(0xFFFF_FFFF);
                    let mark = block
                        .get_str("mark")
                        .or_else(|| block.get_str("reason"))
                        .unwrap_or("Your IP is listed on a DNSBL")
                        .to_string();
                    let score = block
                        .get_i64("score")
                        .and_then(|n| i32::try_from(n).ok())
                        .unwrap_or(0);
                    dnsbl.push(DnsBlConfig {
                        name,
                        host: host_str,
                        bitmask,
                        action,
                        mark,
                        score,
                    });
                }

                "WebIRC" => {
                    let password = match block.get_str("password") {
                        Some(p) => p.to_string(),
                        None => {
                            tracing::warn!("WebIRC block missing password; ignoring");
                            continue;
                        }
                    };
                    webirc.push(WebIrcConfig {
                        password,
                        host: block.get_str("host").map(|s| s.to_string()),
                        description: block
                            .get_str("description")
                            .map(|s| s.to_string()),
                    });
                }

                "Kill" => {
                    // Kill blocks match on host (user@host glob),
                    // optionally ip (CIDR or glob). At least one
                    // must be present; silently drop malformed
                    // entries rather than bailing the whole
                    // config so a typo doesn't brick the server.
                    let host = block.get_str("host").map(|s| s.to_string());
                    let ip = block.get_str("ip").map(|s| s.to_string());
                    if host.is_none() && ip.is_none() {
                        tracing::warn!(
                            "Kill block missing both host and ip; ignoring"
                        );
                    } else {
                        kills.push(KillConfig {
                            host: host.unwrap_or_else(|| "*".into()),
                            ip,
                            reason: block
                                .get_str("reason")
                                .unwrap_or("Banned")
                                .to_string(),
                        });
                    }
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
            kills,
            webirc,
            dnsbl,
            features,
        })
    }

    /// Get client-facing (non-server) port configs.
    pub fn client_ports(&self) -> impl Iterator<Item = &PortConfig> {
        self.ports.iter().filter(|p| !p.server)
    }
}

/// Parse a comma-separated DNSBL index list (e.g. `"2,3,5,6"`)
/// into a u32 bitmask. Each numeric token sets the bit at that
/// index; tokens > 31 are silently dropped. An empty / all-junk
/// input yields `0xFFFFFFFF` ("match any reply") to mirror the C
/// behaviour in dnsbl.c::dnsbl_parse_index.
fn parse_dnsbl_index(s: &str) -> u32 {
    let mut mask: u32 = 0;
    for tok in s.split([',', ' ', '\t']) {
        let tok = tok.trim();
        if tok.is_empty() {
            continue;
        }
        if let Ok(v) = tok.parse::<u32>()
            && v < 32
        {
            mask |= 1u32 << v;
        }
    }
    if mask == 0 { 0xFFFF_FFFF } else { mask }
}

/// Depth-first walk over top-level items, flattening Block entries
/// into `out` and chasing Include directives recursively. `seen`
/// tracks canonicalised paths so a cycle (A → B → A) gets detected
/// on the second visit rather than recursing forever. Missing
/// include files log a warning and continue — same behaviour the
/// original non-recursive code had, which is what nefarious2's
/// ircd_parser.y does for typo-resilience.
fn collect_blocks(
    items: Vec<TopLevel>,
    base_dir: &Path,
    out: &mut Vec<Block>,
    seen: &mut std::collections::HashSet<std::path::PathBuf>,
) -> Result<(), ConfigError> {
    for item in items {
        match item {
            TopLevel::Block(b) => out.push(b),
            TopLevel::Include(path) => {
                let full_path = base_dir.join(&path);
                let canonical = std::fs::canonicalize(&full_path).unwrap_or(full_path.clone());
                if !seen.insert(canonical.clone()) {
                    tracing::warn!(
                        "include cycle detected at {}; skipping",
                        full_path.display()
                    );
                    continue;
                }
                match std::fs::read_to_string(&full_path) {
                    Ok(content) => {
                        let include_dir = full_path.parent().unwrap_or(base_dir);
                        let sub_items = parse_config(&content)
                            .map_err(|e| ConfigError::Parse(format!("in {path}: {e}")))?;
                        // Recurse so nested includes resolve from
                        // the included file's directory, letting
                        // operators use relative paths that mean
                        // what they say.
                        collect_blocks(sub_items, include_dir, out, seen)?;
                    }
                    Err(e) => {
                        tracing::warn!("could not read include file {}: {}", path, e);
                    }
                }
            }
        }
    }
    Ok(())
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
