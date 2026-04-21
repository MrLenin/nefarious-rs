# Nefarious IRCd — Rust Migration Roadmap

**Status**: Planning / Investigation  
**Date**: 2026-04-20  
**Author**: Claude (with direction from Rubin)

## Executive Summary

Nefarious IRCd is ~147K lines of C across 335 source files, implementing a full P10-protocol IRC server with IRCv3.2+ extensions, bouncer persistence, Keycloak integration, and federated chat history. This document evaluates migration strategies to Rust and proposes a phased roadmap.

The core recommendation is a **parallel rewrite** rather than incremental FFI migration, driven by the tight coupling of global state, macro-heavy accessor patterns, and the event loop architecture that touches every subsystem.

---

## Table of Contents

1. [Codebase Profile](#1-codebase-profile)
2. [Migration Strategy Analysis](#2-migration-strategy-analysis)
3. [Rust Ecosystem Mapping](#3-rust-ecosystem-mapping)
4. [Architecture Design](#4-architecture-design)
5. [Phased Roadmap](#5-phased-roadmap)
6. [Risk Analysis](#6-risk-analysis)
7. [Testing Strategy](#7-testing-strategy)
8. [Appendix: Subsystem Catalog](#appendix-subsystem-catalog)

---

## 1. Codebase Profile

### Scale

| Metric | Count |
|--------|-------|
| C source files (.c) | 237 |
| Header files (.h) | 98 |
| Total lines of C | ~147,000 |
| Message handlers (m_*.c) | 124 |
| Feature flags | 200+ |
| External library deps | 8 |

### Top 10 Largest Files

| File | Lines | Subsystem |
|------|-------|-----------|
| channel.c | 5,616 | Channel management |
| m_chathistory.c | 4,860 | Chat history (IRCv3) |
| bouncer_session.c | 4,840 | Bouncer persistence |
| history.c | 4,172 | History storage (MDBX) |
| send.c | 3,442 | Message routing |
| s_auth.c | 3,415 | Client authentication |
| s_user.c | 3,176 | User lifecycle |
| sasl_auth.c | 2,216 | SASL/Keycloak auth |
| metadata.c | 2,171 | Metadata persistence |
| ircd_snprintf.c | 2,169 | Formatted output |

### External Dependencies

| Library | Purpose | Rust Equivalent |
|---------|---------|-----------------|
| OpenSSL | TLS, crypto | `rustls` + `ring` or `openssl` crate |
| libmdbx | Persistent KV store | `heed` (LMDB bindings) or `libmdbx` crate |
| zstd | Compression | `zstd` crate |
| libcurl | HTTP client (Keycloak) | `reqwest` |
| libjansson | JSON parsing | `serde_json` |
| libgit2 | Config sync | `git2` crate |
| libmaxminddb | GeoIP | `maxminddb` crate |
| GeoIP (legacy) | GeoIP fallback | Drop (use maxminddb only) |

### Architectural Characteristics

- **Single-threaded event loop** with platform-specific I/O engines (epoll, kqueue, poll, select)
- **Thread pool** only for CPU-bound work (bcrypt/PBKDF2 password hashing, async logging)
- **Heavy global mutable state**: `GlobalClientList`, `GlobalChannelList`, `GlobalConfList`, `me` (local server)
- **Macro-heavy encapsulation**: ~250 accessor macros wrapping struct field access
- **Intrusive linked lists**: `SLink` (singly) and `DLink` (doubly) threaded through structs
- **Pre-allocated freelists**: Client, Connection, SLink, DLink recycled rather than freed
- **Bit-flag systems**: Flags, Privs, channel modes, membership flags as custom bit arrays
- **Tagged union polymorphism**: SLink value union for type-erased list elements

---

## 2. Migration Strategy Analysis

### Option A: Incremental FFI Migration

Replace C subsystems one at a time with Rust equivalents, connected via C-Rust FFI.

**Advantages:**
- Production remains on working C code throughout
- Each subsystem can be validated independently
- Lower risk per step

**Disadvantages:**
- FFI boundary overhead for hot paths (message routing, channel ops)
- Global mutable state (`GlobalClientList`, etc.) requires `unsafe` Rust or complex synchronization at FFI boundary
- Macro accessor pattern (250+ macros like `cli_name(c)`, `cli_sock_ip(c)`) creates enormous FFI surface
- Linked list structures with embedded pointers are painful across FFI
- The event loop touches everything — migrating it means migrating all callbacks simultaneously
- Two build systems (autotools + cargo) must coexist
- Estimated 40-60% of effort spent on FFI glue that gets thrown away

**Verdict:** Not recommended. The coupling is too tight and the accessor pattern too pervasive.

### Option B: Parallel Rewrite (Recommended)

Build a new Rust IRC server that implements the same protocol and feature set, validated against the same test infrastructure. The C codebase serves as the authoritative reference.

**Advantages:**
- Clean Rust architecture from the ground up (ownership, async, type safety)
- No FFI complexity or unsafe blocks for interop
- Can leverage modern Rust async ecosystem (tokio) instead of hand-rolled event loop
- Opportunity to simplify: the 124 separate m_*.c handler files can become a more unified dispatch system
- Test suite (irctest, vitest) validates compatibility without sharing code
- Natural point to address known architectural debt

**Disadvantages:**
- Longer time to first production deployment
- Risk of feature drift between C and Rust versions
- Must faithfully reproduce P10 protocol quirks and edge cases
- Bouncer/persistence compatibility requires identical MDBX schema

**Verdict:** Recommended. The architecture maps well to Rust idioms, and the existing test infrastructure provides a compatibility safety net.

### Option C: Hybrid — Rust Core, C Handlers via FFI

Write the core (event loop, client/channel state, networking) in Rust, but keep message handlers as C functions called via FFI during the transition.

**Advantages:**
- Gets Rust benefits for the hot path quickly
- 124 handlers can be migrated individually over time
- Handlers have relatively clean interfaces (Message struct with function pointers)

**Disadvantages:**
- Still requires extensive FFI for Client/Channel/Connection structs
- Handler functions deeply reference global state and accessor macros
- Build system complexity remains

**Verdict:** Viable as a variant of Option B if handler migration becomes the bottleneck.

---

## 3. Rust Ecosystem Mapping

### Core Framework

| C Component | Rust Replacement | Notes |
|-------------|-----------------|-------|
| Event loop (engine_epoll/kqueue) | `tokio` | Industry standard async runtime; epoll/kqueue/io_uring |
| Socket layer (s_bsd.c) | `tokio::net` | TcpListener, TcpStream with async read/write |
| TLS (ssl.c) | `tokio-rustls` | Pure Rust TLS, or `tokio-openssl` for compat |
| WebSocket (websocket.c) | `tokio-tungstenite` | Full WebSocket support |
| Message queues (msgq.c) | `tokio::sync::mpsc` | Channel-based message passing |
| Timer events | `tokio::time` | Sleep, interval, timeout |
| Thread pool | `tokio::task::spawn_blocking` | For CPU-bound work |
| DNS resolver (ircd_reslib.c) | `trust-dns` / `hickory-resolver` | Async DNS |

### Data & Persistence

| C Component | Rust Replacement | Notes |
|-------------|-----------------|-------|
| libmdbx (KV store) | `heed` or `libmdbx-rs` | `heed` is higher-level, LMDB-compatible |
| JSON (libjansson) | `serde_json` | Zero-copy deserialization available |
| Zstd compression | `zstd` crate | Direct bindings, well-maintained |
| Configuration parser (flex/yacc) | `nom`, `pest`, or `serde` | Consider TOML/YAML for new config format |
| IP address handling | `std::net::IpAddr` | Native support, no custom encoding needed |

### Protocol & Auth

| C Component | Rust Replacement | Notes |
|-------------|-----------------|-------|
| P10 protocol (parse.c) | Custom parser with `nom` | P10 is line-based, nom handles well |
| IRC message parsing | `irc-proto` crate or custom | May need custom for P10 extensions |
| SASL (sasl_auth.c) | `rsasl` or custom | PLAIN/EXTERNAL/SCRAM-SHA-256 |
| HTTP client (libcurl) | `reqwest` | Async, connection pooling built-in |
| OAuth/OIDC (libkc) | `openidconnect` crate | Native Rust OIDC |
| bcrypt/PBKDF2 | `argon2`/`bcrypt`/`pbkdf2` crates | Pure Rust implementations |
| Base64 (numnicks) | `base64` crate | Custom alphabet for P10 encoding |

### Operational

| C Component | Rust Replacement | Notes |
|-------------|-----------------|-------|
| GeoIP (libmaxminddb) | `maxminddb` crate | Pure Rust reader |
| Git sync (libgit2) | `git2` crate (libgit2 bindings) | Or `gitoxide` for pure Rust |
| Logging (ircd_log.c) | `tracing` | Structured logging, async-compatible |
| Signal handling | `tokio::signal` | Async signal streams |
| Metrics/stats | `prometheus` crate | Modern observability |

---

## 4. Architecture Design

### 4.1 Core Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     tokio runtime                        │
├──────────┬──────────┬───────────┬────────────────────────┤
│ Listener │ Listener │ Listener  │  S2S Connector         │
│ :6667    │ :6697    │ :8443 WS  │  (P10 links)           │
├──────────┴──────────┴───────────┴────────────────────────┤
│              Connection Manager (per-conn tasks)          │
│  ┌─────────────────────────────────────────────────┐     │
│  │  Connection { reader_task, writer_task, state }  │     │
│  │  - Codec: IRC line framing / WebSocket          │     │
│  │  - TLS: rustls layer                            │     │
│  │  - Auth: SASL state machine                     │     │
│  └─────────────────────────────────────────────────┘     │
├──────────────────────────────────────────────────────────┤
│              Message Dispatcher                           │
│  - Command routing (HashMap<&str, Handler>)              │
│  - Permission checking                                    │
│  - Rate limiting                                          │
├─────────┬──────────┬───────────┬─────────────────────────┤
│ Channel │ Client   │ Server   │ Services                 │
│ Manager │ Registry │ Link Mgr │ (Bouncer, History, etc.) │
├─────────┴──────────┴───────────┴─────────────────────────┤
│              Persistence Layer (MDBX)                     │
│  - Bouncer sessions                                       │
│  - Chat history                                           │
│  - Metadata                                               │
│  - WebPush subscriptions                                  │
└──────────────────────────────────────────────────────────┘
```

### 4.2 Key Design Decisions

#### Ownership Model

The C codebase uses global linked lists with raw pointers everywhere. In Rust:

```rust
// Central state owned by the server, shared via Arc
struct ServerState {
    clients: DashMap<Numeric, Arc<ClientState>>,
    channels: DashMap<ChannelName, Arc<RwLock<Channel>>>,
    servers: DashMap<ServerNumeric, Arc<ServerLink>>,
    config: ArcSwap<Config>,
    features: ArcSwap<Features>,
}

// Each connection task holds references, not ownership
struct ConnectionTask {
    state: Arc<ServerState>,
    client: Arc<ClientState>,
    reader: FramedRead<...>,
    writer: mpsc::Sender<Message>,
}
```

**Why DashMap**: Concurrent hash map avoids a single lock bottleneck. Channel operations (JOIN/PART/MODE) lock individual channels, not the whole map.

**Why Arc<RwLock<Channel>>**: Multiple readers (NAMES, WHO, message delivery) with exclusive writers (MODE, KICK, TOPIC). The C code achieves this implicitly through single-threading.

#### Message Routing

Replace the 124 separate `m_*.c` files with a trait-based handler registry:

```rust
#[async_trait]
trait MessageHandler: Send + Sync {
    fn command(&self) -> &str;
    fn token(&self) -> Option<&str>;  // P10 token
    fn min_params(&self) -> usize;

    async fn handle_client(&self, ctx: &mut ClientContext, msg: &Message) -> Result<()>;
    async fn handle_server(&self, ctx: &mut ServerContext, msg: &Message) -> Result<()>;
    // Optional: handle_unreg, handle_oper — default to error
}

// Registration via inventory or manual
fn register_handlers(registry: &mut HandlerRegistry) {
    registry.add(PrivmsgHandler);
    registry.add(JoinHandler);
    registry.add(ModeHandler);
    // ...
}
```

Each handler can still live in its own file/module for organization, but the dispatch is a simple HashMap lookup instead of a trie.

#### P10 Numeric System

```rust
/// Server numeric: 2 base64 chars (0-4095)
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct ServerNumeric(u16);

/// Client numeric: server + 3 base64 chars (0-262143)
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
struct ClientNumeric {
    server: ServerNumeric,
    local: u32,
}

impl ClientNumeric {
    fn encode(&self) -> [u8; 5] { /* base64 encoding */ }
    fn decode(s: &[u8; 5]) -> Self { /* base64 decoding */ }
}
```

#### Bouncer Sessions

The bouncer system maps naturally to Rust's async model:

```rust
struct BouncerSession {
    token: SessionToken,        // 64-char base64
    account: AccountName,
    state: AtomicCell<SessionState>,  // ACTIVE | HOLDING | DESTROYING
    primary: RwLock<Option<ClientNumeric>>,
    aliases: RwLock<Vec<AliasInfo>>,
    channels: RwLock<Vec<ChannelMembership>>,
    hold_timer: Option<JoinHandle<()>>,  // tokio task for expiry
}
```

MDBX persistence uses the same schema for cross-version compatibility during migration.

#### Configuration

Replace the flex/yacc parser with a structured format. Two options:

**Option A: Keep ircd.conf syntax** — Write a `nom` parser for backward compatibility. Allows drop-in replacement.

**Option B: New TOML/YAML format** — Cleaner, standard tooling, better error messages. Requires config migration tool.

Recommendation: **Option A for initial release** (zero friction migration), with Option B as a future enhancement. The parser is isolated enough that swapping later is low-risk.

### 4.3 Concurrency Model

The C codebase is single-threaded with an event loop. Rust opens up two paths:

**Path 1: Single-threaded tokio (current_thread runtime)**
- Closest to C behavior
- No synchronization overhead
- Simple reasoning about state
- Limited to one core

**Path 2: Multi-threaded tokio (multi_thread runtime)**
- Scales across cores
- Requires Arc/RwLock/DashMap for shared state
- More complex but handles more connections
- Natural for modern hardware

**Recommendation:** Design for multi-threaded from the start (it's mostly about data structure choice), but support single-threaded mode via runtime configuration. The performance-critical path is message fan-out to channel members, which benefits from parallelism.

---

## 5. Phased Roadmap

### Phase 0: Foundation (Estimated: 4-6 weeks of focused work)

**Goal:** Minimal IRC server that can accept connections, register users, and join channels.

**Deliverables:**
- [ ] Project scaffolding (cargo workspace, CI, Docker build)
- [ ] IRC line protocol codec (tokio-util `Codec`)
- [ ] Connection acceptance and TLS termination
- [ ] Client registration (NICK/USER)
- [ ] PING/PONG keepalive
- [ ] Basic message dispatch framework
- [ ] JOIN/PART/PRIVMSG/NOTICE to channels
- [ ] Channel creation and MODE basics (+o, +v, +m, +n, +t, +i, +k, +l)
- [ ] QUIT and connection cleanup
- [ ] WHO/WHOIS/NAMES/LIST
- [ ] Numeric replies (001-005, 353, 366, etc.)
- [ ] ISUPPORT (005) advertisement
- [ ] Basic logging with `tracing`

**Validation:** Connect with a standard IRC client, join a channel, chat.

### Phase 1: Protocol Completeness (6-8 weeks)

**Goal:** Full RFC 2812 + P10 compliance. Can link to existing C Nefarious servers.

**Deliverables:**
- [ ] P10 server-to-server protocol
  - [ ] Numeric allocation and management
  - [ ] Server handshake and burst
  - [ ] Nick/channel burst parsing and generation
  - [ ] SQUIT handling and netsplit recovery
- [ ] Complete channel modes (all Nefarious extensions)
- [ ] User modes
- [ ] Operator system (OPER command, privilege levels)
- [ ] KICK, INVITE, TOPIC
- [ ] Ban system (+b, +e exceptions)
- [ ] K-line, G-line, Shun, Z-line
- [ ] MOTD, ADMIN, INFO, VERSION, STATS
- [ ] DNS resolution (async)
- [ ] IP cloaking
- [ ] Configuration file parser (ircd.conf format)
- [ ] Connection classes with limits
- [ ] Flood protection and throttling

**Validation:** Link Rust server to C Nefarious, burst state, route messages across the link. Run irctest suite.

### Phase 2: IRCv3 Capabilities (4-6 weeks)

**Goal:** Full IRCv3.2+ capability set matching current Nefarious.

**Deliverables:**
- [ ] CAP negotiation (LS, REQ, ACK, NEW, DEL)
- [ ] `message-tags` and `msgid`
- [ ] `server-time`
- [ ] `echo-message`
- [ ] `labeled-response`
- [ ] `batch` (NETSPLIT, NETJOIN, chathistory)
- [ ] `multi-prefix`
- [ ] `account-notify`, `account-tag`
- [ ] `extended-join`
- [ ] `setname`
- [ ] `draft/multiline`
- [ ] `sasl` (mechanism advertisement)
- [ ] `away-notify`
- [ ] Standard replies (FAIL/WARN/NOTE)

**Validation:** Test with modern IRC clients (Textual, The Lounge, Kiwi IRC). Verify CAP negotiation with irctest.

### Phase 3: Authentication (4-6 weeks)

**Goal:** Full SASL stack with Keycloak integration.

**Deliverables:**
- [ ] SASL framework with mechanism dispatch
- [ ] SASL PLAIN (local validation)
- [ ] SASL EXTERNAL (TLS client certs)
- [ ] SASL OAUTHBEARER (Keycloak ROPC)
- [ ] SASL SCRAM-SHA-256
- [ ] Keycloak HTTP integration (replace libkc/libcurl with reqwest)
  - [ ] Token validation
  - [ ] User lookup
  - [ ] Credential caching (SipHash)
  - [ ] Webhook handler
  - [ ] Cache invalidation (CI token)
- [ ] IAuth protocol support (for iauthd-ts)
- [ ] Account system (P10 AC token)
- [ ] Connection class restrictions (CRFLAG_REQUIRE_SASL, CRFLAG_BOUNCER)

**Validation:** Authenticate via Keycloak, verify SASL flows, test IAuth delegation.

### Phase 4: Persistence (6-8 weeks)

**Goal:** MDBX-backed persistence for bouncer, history, metadata.

**Deliverables:**
- [ ] MDBX integration layer (heed or libmdbx-rs)
- [ ] Bouncer session system
  - [ ] Session create/resume/destroy
  - [ ] HOLD state with timer expiry
  - [ ] Session token management
  - [ ] Alias system (multi-connection)
  - [ ] Cross-server session move
  - [ ] MDBX persistence (compatible schema)
  - [ ] P10 burst of sessions (BS/BX tokens)
- [ ] Chat history
  - [ ] Message storage with MDBX
  - [ ] Zstd compression
  - [ ] CHATHISTORY command (BEFORE, AFTER, AROUND, BETWEEN, LATEST)
  - [ ] History federation (cross-server)
  - [ ] Retention policies
- [ ] Metadata system
  - [ ] Per-user, per-channel metadata
  - [ ] MDBX persistence
  - [ ] TTL and immutable keys
  - [ ] P10 metadata sync (MD/MDQ tokens)
- [ ] Read markers (MR token)
- [ ] WebPush notifications
  - [ ] Subscription management
  - [ ] VAPID key handling
  - [ ] Push delivery

**Validation:** Disconnect/reconnect with bouncer, verify history replay, metadata persistence across restarts.

### Phase 5: Operational Features (3-4 weeks)

**Goal:** Production operational tooling.

**Deliverables:**
- [ ] GeoIP integration (maxminddb)
- [ ] Git-based config sync
- [ ] DNSBL checking
- [ ] /CHECK command
- [ ] /STATS command (full implementation)
- [ ] Paste service (TLS listener)
- [ ] Rehash (config reload without restart)
- [ ] Signal handling (SIGHUP, SIGTERM)
- [ ] Graceful shutdown
- [ ] Connection limiting and IPcheck
- [ ] Watch/monitor notifications

**Validation:** Operational testing — rehash, stats, geoip lookups, paste service.

### Phase 6: Hardening & Migration (4-6 weeks)

**Goal:** Production-ready with migration tooling.

**Deliverables:**
- [ ] Comprehensive fuzzing (P10 parser, IRC parser, SASL)
- [ ] Performance benchmarking vs C version
- [ ] Memory usage profiling
- [ ] Config migration tool (if new format adopted)
- [ ] MDBX database migration/compatibility verification
- [ ] Docker image optimization
- [ ] Documentation (operator guide, migration guide)
- [ ] CI pipeline (build, test, lint, fuzz)

**Validation:** Sustained load testing, irctest full suite pass, production trial.

### Total Estimated Timeline

| Phase | Duration | Cumulative |
|-------|----------|------------|
| Phase 0: Foundation | 4-6 weeks | 4-6 weeks |
| Phase 1: Protocol | 6-8 weeks | 10-14 weeks |
| Phase 2: IRCv3 | 4-6 weeks | 14-20 weeks |
| Phase 3: Auth | 4-6 weeks | 18-26 weeks |
| Phase 4: Persistence | 6-8 weeks | 24-34 weeks |
| Phase 5: Operations | 3-4 weeks | 27-38 weeks |
| Phase 6: Hardening | 4-6 weeks | 31-44 weeks |

**Approximately 8-11 months** of focused development effort. Phases 2 and 3 can partially overlap. Phase 5 items can be interleaved throughout.

---

## 6. Risk Analysis

### High Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| P10 protocol edge cases | Incompatible burst/routing causes netsplits | Use C code as reference, extensive irctest coverage, test linking Rust↔C servers |
| Bouncer session compatibility | Users lose persistent sessions during migration | Identical MDBX schema, migration verification tool, fallback to C server |
| MDBX schema evolution | Data loss or corruption on upgrade | Versioned schema with migration functions, backup before upgrade |
| Feature parity gap | Production can't switch until 100% compatible | Prioritize by usage — bouncer and chathistory before paste service |

### Medium Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Async complexity | Deadlocks, race conditions in concurrent state | Start with single-threaded runtime, graduate to multi-threaded |
| Performance regression | Rust overhead from Arc/RwLock | Benchmark early (Phase 1), optimize hot paths |
| Keycloak integration differences | Auth failures in production | Identical test suite, shared Keycloak instance in CI |
| ircd.conf parser fidelity | Config migration breaks | Fuzz test parser against C parser output |

### Low Risk

| Risk | Impact | Mitigation |
|------|--------|------------|
| Rust ecosystem stability | Dependency breaking changes | Pin versions, minimal deps |
| Build complexity | Longer CI times | Cargo workspace, incremental compilation |
| Developer onboarding | Slower contribution | Rust is well-documented, IRC logic stays the same |

---

## 7. Testing Strategy

### Compatibility Testing

The existing test infrastructure is the primary validation tool:

1. **irctest** — Protocol compliance test suite (already in repo). Run against both C and Rust servers; diff results.
2. **Vitest suite** — Integration tests in `tests/`. Test X3 services interaction, Keycloak auth, bouncer behavior.
3. **CMocka unit tests** — Port to Rust `#[test]` as each subsystem is rewritten.

### New Testing

4. **Property-based testing** — `proptest` for P10 message parsing (roundtrip: parse → serialize → parse).
5. **Fuzzing** — `cargo-fuzz` for protocol parsers and SASL state machines.
6. **Cross-linking test** — Link Rust server to C Nefarious, burst state, verify consistency.
7. **Bouncer compatibility test** — Create session on C server, restore on Rust server (shared MDBX).
8. **Load testing** — `locust` or custom tool simulating thousands of concurrent users.

### CI Pipeline

```
cargo check → cargo clippy → cargo test → cargo fuzz (nightly)
                                    ↓
                              irctest suite
                                    ↓
                          cross-link test (Rust ↔ C)
```

---

## Appendix: Subsystem Catalog

### Dependency Tiers (migration order)

**Tier 0 — Zero dependencies (migrate first)**
| Subsystem | Files | Lines | Rust Notes |
|-----------|-------|-------|------------|
| String utilities | ircd_string.c/h | 1,200 | Mostly replaced by std::str |
| Memory allocation | ircd_alloc.c/h | 200 | Replaced by standard allocator |
| Logging | ircd_log.c/h | 1,000 | Replace with `tracing` |
| Numeric formatting | ircd_snprintf.c/h | 2,200 | `format!()` macro |
| Character tables | ircd_chattr.c/h | 300 | Lookup tables, trivial port |
| Base64/numnicks | numnicks.c/h | 400 | Custom base64 codec |
| Random | random.c/h | 100 | `rand` crate |

**Tier 1 — Core services**
| Subsystem | Files | Lines | Rust Notes |
|-----------|-------|-------|------------|
| Event loop | ircd_events.c + 5 engines | 3,500 | Replace with tokio |
| Timers | (in ircd_events) | — | `tokio::time` |
| Socket layer | s_bsd.c/h | 1,700 | `tokio::net` |
| TLS | ssl.c/h | 1,000 | `tokio-rustls` |
| WebSocket | websocket.c/h | 800 | `tokio-tungstenite` |
| DNS | ircd_reslib.c, res.c | 1,600 | `hickory-resolver` |
| Data buffers | dbuf.c, msgq.c | 1,000 | `bytes` crate / channels |

**Tier 2 — Protocol**
| Subsystem | Files | Lines | Rust Notes |
|-----------|-------|-------|------------|
| IRC parser | parse.c/h | 2,100 | `nom` or hand-rolled |
| Message dispatch | msg.h + handlers | ~15,000 | Trait-based registry |
| Numeric replies | s_err.c, numeric.h | 2,200 | Enum with Display impl |
| P10 encoding | s_numeric.c, numnicks | 800 | Newtype wrappers |
| ISUPPORT | supported.c/h | 400 | String builder |

**Tier 3 — State management**
| Subsystem | Files | Lines | Rust Notes |
|-----------|-------|-------|------------|
| Client registry | client.c/h | 1,500 | DashMap<Numeric, Arc<Client>> |
| Channel manager | channel.c/h | 6,200 | DashMap + per-channel RwLock |
| User lifecycle | s_user.c/h | 3,200 | Connection state machine |
| Server links | s_serv.c/h | 1,500 | P10 link management |
| Configuration | s_conf.c/h | 2,100 | Parsed config struct |
| Features | ircd_features.c/h | 1,700 | Typed feature registry |
| Hash tables | hash.c/h | 600 | Standard HashMap |
| Lists | list.c/h | 500 | Vec, VecDeque, etc. |

**Tier 4 — Features & persistence**
| Subsystem | Files | Lines | Rust Notes |
|-----------|-------|-------|------------|
| Bouncer | bouncer_session.c/h | 4,900 | Async state machine |
| Chat history | history.c, m_chathistory.c | 9,000 | MDBX + query engine |
| Metadata | metadata.c, m_metadata.c | 3,700 | MDBX KV store |
| SASL/Auth | sasl_auth.c, m_authenticate.c | 3,500 | State machine + reqwest |
| Keycloak adapter | ircd_kc_adapter.c/h | 800 | reqwest + serde |
| Webhook | sasl_webhook.c/h | 600 | reqwest |
| IAuth | s_auth.c/h | 3,400 | Protocol adapter |
| WebPush | webpush.c/h, webpush_store.c/h | 1,800 | Web Push crate |
| GeoIP | ircd_geoip.c/h | 400 | maxminddb crate |
| Git sync | gitsync.c/h | 1,500 | git2 crate |
| Paste service | paste_listener.c/h | 1,200 | Simple TLS server |
| IP cloaking | ircd_cloaking.c/h | 300 | HMAC-based, trivial |
| Bans (G/K/Z/Shun) | gline.c, shun.c, zline.c | 3,600 | Timed ban collections |
| CRDT/HLC | crdt_hlc.c/h | 200 | Hybrid logical clock |

### Message Handler Catalog (124 files)

The message handlers are the bulk of the file count but not the bulk of the complexity. Most are 50-200 lines. The notable exceptions:

| Handler | Lines | Complexity |
|---------|-------|------------|
| m_chathistory.c | 4,860 | High — query parsing, pagination, federation |
| m_batch.c | 1,972 | Medium — multiline state management |
| m_metadata.c | 1,513 | Medium — MDBX persistence, P10 sync |
| m_check.c | 1,163 | Medium — diagnostic output formatting |
| m_bouncer.c | ~800 | Medium — session management commands |
| m_cap.c | ~600 | Medium — capability negotiation |
| m_mode.c | ~500 | Medium — complex mode parsing |
| Most others | 50-200 | Low — straightforward command handling |

---

## Design Considerations for Future Discussion

1. **Config format**: Keep ircd.conf for compatibility or move to TOML? Could support both with a compatibility layer.

2. **Plugin system**: Rust's trait objects could enable a plugin architecture for handlers, reducing the need to modify core code for new features.

3. **X3 merger path**: If Nefarious moves to Rust, the eventual X3-into-Nefarious merge (per project direction) becomes a Rust services implementation rather than C integration. This is architecturally cleaner — services become modules within the server, not a separate process.

4. **WebSocket-first**: With tokio-tungstenite, WebSocket becomes a first-class transport rather than a bolt-on. Could simplify the listener architecture.

5. **Observability**: Rust's `tracing` ecosystem enables structured logging, distributed tracing, and metrics from day one. Much richer than the current syslog-style logging.

6. **Memory safety**: The entire class of bugs around `ircd_strncpy` buffer sizes, use-after-free in connection cleanup, and double-free in linked list management disappears. The bouncer system's complex lifetime management (ghost clients, alias promotion, session move) becomes enforced by the type system.

