# CLAUDE.md — nefarious-rs

## Project Overview

Rust rewrite of Nefarious IRCd. Parallel implementation validated against the same test infrastructure as the C version.

## Build & Run

```bash
cargo build                    # debug build
cargo build --release          # release build
cargo test --workspace         # run all tests
cargo clippy --workspace       # lint

# Docker
docker build -t nefarious-rs .
```

## Architecture

Cargo workspace with three crates:

- **irc-proto** — IRC message parsing/serialization, tokio-util Codec for line framing
- **irc-config** — nom-based parser for ircd.conf format (C Nefarious compatible)
- **nefarious** — main server binary

### Runtime
- tokio async runtime (multi-threaded)
- tokio-openssl for TLS (PEM cert compatibility with C version)
- DashMap for concurrent client/channel registries

### Key Types
- `irc_proto::Message` — parsed IRC message (tags, source, command, params)
- `irc_proto::IrcCodec` — tokio-util Codec for IRC line framing
- `irc_config::Config` — parsed ircd.conf configuration

## Configuration

Uses the same ircd.conf format as C Nefarious. Block-based syntax:
```
General { name = "server.name"; numeric = 1; };
Port { port = 6667; ssl = no; };
```

## Testing

```bash
cargo test --workspace         # unit tests
# Integration: connect with irssi/weechat to localhost:6667
```
