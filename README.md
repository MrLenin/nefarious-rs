# nefarious-rs

Rust rewrite of [Nefarious IRCd](https://github.com/MrLenin/nefarious2/tree/ircv3.2-upgrade) — a full-featured IRC server implementing P10 server-to-server protocol, IRCv3.2+ capabilities, SASL authentication, and bouncer persistence. Developed as a parallel rewrite validated against the same protocol test infrastructure as the C version.

**Wire format compatibility with C Nefarious is a hard requirement.** Internal improvements are welcome; P10/IRC protocol divergence is not.

---

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Foundation — single-server IRC daemon | ✅ Complete |
| Phase 1 | P10 server linking | ✅ Complete |
| Phase 2 | IRCv3 capabilities | ✅ Complete |
| Phase 3 | Authentication (SASL + Keycloak) | 🟡 In Progress |
| Phase 4 | Persistence (bouncer, chat history, metadata) | ⬜ Planned |
| Phase 5 | Operational features | 🟡 In Progress |
| Phase 6 | Hardening and migration tooling | ⬜ Planned |

See [docs/roadmap.md](docs/roadmap.md) for the full phased plan.

---

## Architecture

Cargo workspace with four crates:

```
nefarious-rs/
├── crates/
│   ├── irc-proto/      # IRC (client) message parsing and serialization
│   ├── irc-config/     # ircd.conf format parser (C Nefarious-compatible)
│   ├── p10-proto/      # P10 server-to-server protocol encoding/decoding
│   └── nefarious/      # Main server binary
```

### Runtime

- **tokio** multi-threaded async runtime
- **tokio-openssl** for TLS (PEM cert compatibility with C Nefarious)
- **DashMap** for concurrent client, channel, and server registries
- **nom** for ircd.conf parsing

### Key Types

| Type | Crate | Purpose |
|------|-------|---------|
| `irc_proto::Message` | irc-proto | Parsed IRC message (tags, source, command, params) |
| `irc_proto::IrcCodec` | irc-proto | tokio-util Codec for IRC line framing |
| `p10_proto::P10Message` | p10-proto | Parsed P10 server message with numeric prefix |
| `p10_proto::ClientNumeric` | p10-proto | 5-char YYXXX P10 user identifier |
| `irc_config::Config` | irc-config | Parsed ircd.conf configuration |
| `nefarious::state::ServerState` | nefarious | Global shared server state (Arc-wrapped) |
| `nefarious::client::Client` | nefarious | Per-connection client state |
| `nefarious::channel::Channel` | nefarious | Channel state (membership, modes, bans) |

### Server-to-Server (P10)

The `s2s/` module handles P10 federation with other Nefarious servers:

- **Handshake**: `PASS` + `SERVER` exchange
- **Burst**: sends all local users (`N`), channels (`B`), G-lines, ban-except lists, then `END_OF_BURST`
- **Steady state**: routes `PRIVMSG`/`NOTICE`/`JOIN`/`PART`/`MODE`/`KICK`/`TOPIC`/`QUIT`/`NICK` across the link
- **Numerics**: 18-bit per-server slot pool with recycling (YYXXX format)
- **Account propagation**: `AC` token with C/H/S/A/D LOC passthrough
- **OPMODE / CLEARMODE**: oper-invoked channel mode override tokens
- **SILENCE propagation**: `U` token broadcasts per-client silence lists
- **HLC msgids**: hybrid logical clock seeded msgids with compact `@A` S2S tags
- **BS/BX**: baseline bouncer session and transfer token handling
- **Autoconnect**: Connect blocks with `autoconnect=yes` retry on disconnect
- **Outbound TLS**: S2S links support `ssl=yes` for encrypted peering

---

## Implemented Features

### Client Protocol

| Feature | Status |
|---------|--------|
| NICK/USER registration | ✅ |
| PING/PONG keepalive | ✅ |
| JOIN/PART/TOPIC/KICK/INVITE | ✅ |
| PRIVMSG/NOTICE (channel + private) | ✅ |
| Channel modes (+n +t +m +i +s +p +k +l) | ✅ |
| Extended channel modes (+C +N +c +D +M +Q +R +r +S +T +u +z +L) | ✅ |
| Membership modes (+o +v +h) | ✅ |
| User modes (+w +o +i +s +x +R) | ✅ |
| WHO/WHOIS/USERHOST/USERIP/ISON | ✅ |
| AWAY + away-notify | ✅ |
| WALLOPS | ✅ |
| OPER + privilege propagation | ✅ |
| NAMES/LIST | ✅ |
| STATS (l/o/G/S/Z/J/u) | ✅ |
| TIME/ADMIN/INFO/LINKS/MAP | ✅ |
| WHOWAS | ✅ |
| Ban lists (+b / +e) | ✅ |
| KILL — oper-forced disconnect | ✅ |
| SETHOST — oper host change | ✅ |
| WEBIRC — trusted-gateway IP passthrough | ✅ |
| SILENCE — per-client sender filter | ✅ |
| WATCH / MONITOR — nick-presence notifications | ✅ |
| NICKDELAY — nick-change rate throttle | ✅ |
| IP crypto cloaking (+x, nefarious2-compatible) | ✅ |
| K-lines — local connect bans | ✅ |
| G-line / Z-line / Shun / Jupe — network bans | ✅ |
| Per-IP clone throttle (IPcheck) | ✅ |
| REHASH — live config reload | ✅ |
| bcrypt oper passwords | ✅ |
| PASS verification against Client blocks | ✅ |

### IRCv3 Capabilities

| Capability | Status |
|------------|--------|
| `server-time` | ✅ |
| `echo-message` | ✅ |
| `account-tag` | ✅ |
| `multi-prefix` | ✅ |
| `userhost-in-names` | ✅ |
| `extended-join` | ✅ |
| `account-notify` | ✅ |
| `away-notify` | ✅ |
| `invite-notify` | ✅ |
| `cap-notify` | ✅ |
| `chghost` / `setname` | ✅ |
| `standard-replies` | ✅ |
| `batch` | ✅ |
| `labeled-response` | ✅ |
| `message-tags` | ✅ |
| `sasl` | ✅ |

### Authentication

| Feature | Status |
|---------|--------|
| Account system (`AccountStore` trait + in-memory backend) | ✅ |
| SASL PLAIN | ✅ |
| SASL EXTERNAL (TLS client cert CN) | ✅ |
| Account propagation (P10 `AC`) | ✅ |
| `sasl` capability advertisement | ✅ |
| SASL SCRAM-SHA-256 | ⬜ Planned |
| SASL OAUTHBEARER | ⬜ Planned |
| Keycloak HTTP integration | ⬜ Planned |
| IAuth protocol | ⬜ Planned |
| Connection class SASL requirements | ⬜ Planned |

### Operational Features (Phase 5)

| Feature | Status |
|---------|--------|
| GeoIP tagging at connect (MaxMind MMDB) | ✅ |
| DNSBL connect-time check | ✅ |
| Git config sync — in-process libgit2 pull + `/GITSYNC` | ✅ |
| TLS cert hot-swap from git repo (atomic `SslAcceptor` reload) | ✅ |
| SSH TOFU host-key pinning for git remote | ✅ |
| `/CHECK` — oper audit for users, channels, servers | ✅ |
| `/REHASH` — full live config reload | ✅ |
| Graceful shutdown with client notice + peer SQUIT (SIGINT/SIGTERM) | ✅ |
| Per-IP clone throttle (IPcheck, rolling window) | ✅ |
| Autoconnect + outbound TLS for S2S links | ✅ |
| Background ban-expiry sweeper | ✅ |
| Paste service (TLS listener) | ⬜ Planned |

---

## Build

**Requirements:** Rust 1.88+, OpenSSL (for the `nefarious` binary)

```bash
# Build all crates
cargo build

# Release build
cargo build --release

# Library crates only (no OpenSSL needed)
cargo build -p irc-proto -p irc-config -p p10-proto

# Lint
cargo clippy --workspace

# Tests
cargo test --workspace
```

### Docker

```bash
docker build -t nefarious-rs .
docker run -v $(pwd)/config:/etc/ircd nefarious-rs
```

The Docker image uses a multi-stage build (rust:1.88-bookworm → debian:bookworm-slim) and links OpenSSL dynamically.

---

## Configuration

Uses the same `ircd.conf` block format as C Nefarious. Nested `include "path";` directives are supported with cycle detection.

Supported block types:

| Block | Purpose |
|-------|---------|
| `General` | Server identity (name, numeric, description, vhost, hidden_host_suffix) |
| `Admin` | Location and contact info |
| `Port` | Listening ports (`port`, `ssl`, `websocket`, `vhost`) |
| `Class` | Connection class limits (pingfreq, connectfreq, maxlinks, sendq) |
| `Client` | Client allow-rules (class, ip, host, password, maxlinks) |
| `Operator` | IRC operator definitions (name, password, host, class, local, privs) |
| `Connect` | S2S link blocks (name, host, password, port, class, ssl, autoconnect, hub) |
| `Kill` | Local K-lines — host glob or IP CIDR connect bans |
| `WebIRC` | Trusted gateway passthrough (password, host) |
| `DNSBL` | DNSBL zones (`name`, `host` index list, `bitmask`, `action`: block/block\_all/block\_anon/mark/whitelist, `mark`, `score`). Legacy aliases `domain`/`reply`/`reason` accepted. |
| `Pseudo "<CMD>"` | User command alias rewritten to PRIVMSG against a services nick (`name`, `nick = AuthServ@x3.services`, optional `prepend`). Powers `/AUTH`, `/MEMOSERV`, etc. |
| `Jupe` | Reserved nicknames; one or more `nick = "csv,of,names";` entries. Refused at NICK with ERR_ERRONEUSNICKNAME. Server-name jupes still use the runtime `/JUPE`. |
| `UWorld` | Trusted services / U-lined servers; one or more `name = "...";` entries. Stored for downstream override checks. |
| `Features` | Key-value network settings (see table below) |

Key `Features` entries:

| Key | Purpose |
|-----|---------|
| `NETWORK` | Network name (ISUPPORT, welcome message) |
| `SSL_CERTFILE` / `SSL_KEYFILE` | TLS cert and key paths |
| `MMDB_FILE` | Path to MaxMind GeoLite2 MMDB database |
| `GIT_CONFIG_PATH` | Repo path for git config sync |
| `GIT_SYNC_INTERVAL` | Pull interval in seconds (default 300) |
| `GITSYNC_SSH_KEY` | SSH private key for git remote |
| `GITSYNC_HOST_FINGERPRINT` | TOFU-pinned SSH host fingerprint |
| `GITSYNC_CERT_PATH` | Repo-relative cert file to install |
| `GITSYNC_CERT_FILE` | Install destination for cert from repo |
| `IPCHECK_CLONE_LIMIT` | Max connections per IP per window (default 4) |
| `IPCHECK_CLONE_PERIOD` | Rolling window in seconds (default 40) |
| `DNSBL_TIMEOUT` | Per-zone DNS query timeout in seconds (default 5) |
| `DNSBL_CACHETIME` | Per-IP DNSBL result cache TTL in seconds (default 21600) |
| `NICK_DELAY` | Seconds between nick changes (default 30) |
| `MAXCHANNELSPERUSER` | Per-user channel join cap |
| `MAXBANS` | Per-channel ban list cap |

See [config/ircd.conf](config/ircd.conf) for a complete annotated example.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Tracing filter (default: `info`) |
| `NEFARIOUS_ACCOUNTS` | Bootstrap SASL accounts: `alice:secret,bob:pw` (dev only) |
| `SSL_CERT` | TLS certificate path (overrides `Features { SSL_CERTFILE }`) |
| `SSL_KEY` | TLS key path (overrides `Features { SSL_KEYFILE }`) |

---

## Testing

```bash
# Unit tests
cargo test --workspace

# Integration: connect with a standard IRC client
irssi -c localhost -p 6667
```

### Cross-linking with C Nefarious

The Rust server is designed to link with the C version for compatibility validation. Start both servers with matching `Connect` blocks and verify burst exchange and message routing across the link.

The reference C implementation is at `../nefarious2` (ircv3.2-upgrade branch).

---

## Reference Implementation

- **C Nefarious**: `c:\Users\johne\source\repos\nefarious2` (ircv3.2-upgrade branch) — authoritative wire format reference
- **Roadmap**: [docs/roadmap.md](docs/roadmap.md)
- **Phase plans**: [docs/phase-0-foundation.md](docs/phase-0-foundation.md), [docs/phase-1-p10.md](docs/phase-1-p10.md), [docs/phase-2-ircv3.md](docs/phase-2-ircv3.md)
