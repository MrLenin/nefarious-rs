# nefarious-rs

Rust rewrite of [Nefarious IRCd](https://github.com/MrLenin/nefarious2/tree/ircv3.2-upgrade) — a full-featured IRC server implementing P10 server-to-server protocol, IRCv3.2+ capabilities, SASL authentication, and bouncer persistence. Developed as a parallel rewrite validated against the same protocol test infrastructure as the C version.

**Wire format compatibility with C Nefarious is a hard requirement.** Internal improvements are welcome; P10/IRC protocol divergence is not.

---

## Status

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 0 | Foundation — single-server IRC daemon | ✅ Complete |
| Phase 1 | P10 server linking | ✅ Complete (baseline) |
| Phase 2 | IRCv3 capabilities | ✅ Complete |
| Phase 3 | Authentication (SASL + Keycloak) | 🟡 In Progress |
| Phase 4 | Persistence (bouncer, chat history, metadata) | ⬜ Planned |
| Phase 5 | Operational features | ⬜ Planned |
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
- **Burst**: sends all local users (`N`), channels (`B`), then `END_OF_BURST`
- **Steady state**: routes `PRIVMSG`/`NOTICE`/`JOIN`/`PART`/`MODE`/`KICK`/`TOPIC`/`QUIT`/`NICK` across the link
- **Numerics**: 18-bit per-server slot pool with recycling (YYXXX format)
- **Account propagation**: `AC` token for logged-in users

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
| Membership modes (+o +v +h) | ✅ |
| User modes (+w +o +i +s) | ✅ |
| WHO/WHOIS/USERHOST/ISON | ✅ |
| AWAY + away-notify | ✅ |
| WALLOPS | ✅ |
| OPER | ✅ |
| NAMES/LIST | ✅ |
| STATS/TIME/ADMIN/INFO/LINKS/MAP | ✅ (framework) |
| WHOWAS | 🟡 Stub |
| Ban lists (+b) | 🟡 Partial |

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

Uses the same `ircd.conf` block format as C Nefarious:

```
General {
    name        = "rs.example.net";
    numeric     = 2;
    description = "nefarious-rs test server";
};

Port { port = 6667; };
Port { port = 6697; ssl = yes; };

Class {
    name    = "users";
    pingfreq = 90 seconds;
    sendq   = 512 kilobytes;
    maxlinks = 100;
};

Client {
    class = "users";
    ip    = "*@*";
};

Connect {
    name     = "hub.example.net";
    host     = "hub.example.net";
    password = "link-secret";
    port     = 4400;
    class    = "servers";
};
```

See [config/ircd.conf](config/ircd.conf) for a complete example.

### Environment Variables

| Variable | Purpose |
|----------|---------|
| `RUST_LOG` | Tracing filter (default: `info`) |
| `NEFARIOUS_ACCOUNTS` | Bootstrap SASL accounts: `alice:secret,bob:pw` |

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
