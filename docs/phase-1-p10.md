# Phase 1: P10 Server Linking

## Context

Phase 0 delivered a working single-server IRC daemon in Rust. Phase 1 adds P10 server-to-server protocol support so the Rust server can link to the existing C Nefarious and participate in the network — receiving users/channels via burst, routing messages across the link, and handling netsplits.

This is a **receive-first** implementation: we prioritize correctly parsing and processing P10 messages FROM the C server, then sending our own state. This lets us validate incrementally against the real C Nefarious rather than testing in isolation.

**Goal:** `nefarious-rs` links to `nefarious` (C) via a Connect block, exchanges burst, and routes PRIVMSG/NOTICE between local and remote users across the link.

## Scope

### In Scope (Phase 1)
- P10 base64 numeric system (server + client numerics)
- Server handshake (PASS/SERVER exchange)
- Receiving burst: SERVER (S), NICK (N), BURST (B), END_OF_BURST (EB)
- Sending burst: our servers, users, channels
- END_OF_BURST_ACK (EA) exchange
- Message routing across link (PRIVMSG/NOTICE P/O tokens)
- Basic S2S commands: JOIN (J), PART (L), QUIT (Q), MODE (M), KICK (K), TOPIC (T), NICK (N) changes
- PING/PONG (G/Z) keepalive
- SQUIT (SQ) handling — clean disconnect
- ACCOUNT (AC) token — receive and track account state
- CREATE (C) / DESTRUCT (DE) — channel lifecycle from remote

### Out of Scope (Later Phases)
- Outbound autoconnect (we only accept inbound links for now)
- SASL relay (S2S SASL forwarding)
- Metadata (MD/MDQ) burst and sync
- Bouncer session (BS/BX) burst and sync
- Chat history federation (CH)
- Multiline (ML) S2S relay
- S2S message tags (compact @A format)
- G-lines, shuns, jupes, zlines
- Multiple server links (we support one link initially)

## Architecture

### New Crate: `p10-proto`

Separate from `irc-proto` (client protocol) — P10 is a different wire format with numerics, tokens, and different semantics.

```
crates/p10-proto/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── numeric.rs      # Base64 encoding, ServerNumeric, ClientNumeric
│   ├── token.rs        # P10 token → command mapping
│   ├── message.rs      # P10 message parsing (prefix as numeric)
│   └── codec.rs        # P10 line codec (reuse from irc-proto or shared)
```

### New Module in `nefarious` crate: `s2s/`

```
crates/nefarious/src/s2s/
├── mod.rs              # S2S subsystem entry point
├── link.rs             # Server link lifecycle (handshake, burst, steady-state)
├── burst.rs            # Burst generation (send our state) and processing (receive remote state)
├── routing.rs          # Message routing across links
└── handlers.rs         # P10 token handlers (N, B, Q, J, L, M, K, T, AC, etc.)
```

### State Changes

**ServerState** gains:
```rust
/// Remote servers by numeric
pub servers: DashMap<ServerNumeric, Arc<RwLock<RemoteServer>>>,
/// Remote clients by numeric (YY+XXX)
pub remote_clients: DashMap<ClientNumeric, Arc<RwLock<RemoteClient>>>,
/// Our server's P10 numeric
pub numeric: ServerNumeric,
/// Active server links
pub links: DashMap<ServerNumeric, Arc<ServerLink>>,
```

**RemoteServer** — a server we know about (from burst):
```rust
struct RemoteServer {
    name: String,
    numeric: ServerNumeric,
    hop_count: u16,
    description: String,
    uplink: ServerNumeric,     // parent server numeric
    capacity_mask: u32,        // nn_mask for client_list sizing
    flags: ServerFlags,        // hub, ipv6, etc.
    timestamp: u64,
}
```

**RemoteClient** — a user on a remote server (from burst):
```rust
struct RemoteClient {
    nick: String,
    numeric: ClientNumeric,
    server: ServerNumeric,
    user: String,
    host: String,
    realname: String,
    ip: String,
    modes: HashSet<char>,
    account: Option<String>,
    nick_ts: u64,
    channels: HashSet<String>,
}
```

**ServerLink** — an active S2S connection:
```rust
struct ServerLink {
    numeric: ServerNumeric,
    name: String,
    sender: mpsc::Sender<String>,  // raw P10 lines
    state: AtomicCell<LinkState>,  // HANDSHAKE | BURSTING | ACTIVE
}
```

### Channel Changes

Channels need to track remote members alongside local ones. Two options:

**Option A**: Unify — channels store `MemberId` enum that's either `Local(ClientId)` or `Remote(ClientNumeric)`. Simpler routing but more complex member lookups.

**Option B**: Separate maps — `local_members: HashMap<ClientId, Flags>` + `remote_members: HashMap<ClientNumeric, Flags>`. Cleaner separation but duplicated logic.

**Recommended: Option A** — a unified member map avoids duplicating JOIN/PART/MODE logic. Message delivery branches on local vs remote at send time.

```rust
#[derive(Clone, Copy, Hash, Eq, PartialEq)]
enum MemberId {
    Local(ClientId),
    Remote(ClientNumeric),
}
```

### Message Routing

When a local user sends PRIVMSG to a channel:
1. Deliver to local members (existing logic)
2. Send P10 `P` token to server link (new)

When a P10 message arrives from the link:
1. Parse the P10 line (numeric prefix, token, params)
2. Dispatch to handler based on token
3. Handler updates state (e.g., remote user joins channel)
4. Handler delivers to affected local users (e.g., channel members see the JOIN)

## Implementation Order

### Step 1: p10-proto crate — Base64 and numerics
- P10 base64 alphabet (`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]`)
- `inttobase64()` / `base64toint()` — encode/decode
- `ServerNumeric` (2-char) and `ClientNumeric` (5-char) newtypes
- IP address encoding/decoding (IPv4: 6 chars, IPv6: variable with `_` compression)
- Unit tests for known values

### Step 2: p10-proto — Token mapping and message parsing
- Token table: `N`→NICK, `P`→PRIVMSG, `B`→BURST, `S`→SERVER, etc.
- P10 message parser (numeric prefix, token, params)
- P10 message serializer (for outbound)
- Codec (line-based, same framing as IRC but different content)

### Step 3: State refactoring — MemberId, remote tracking
- `MemberId` enum in channel.rs
- `RemoteServer` and `RemoteClient` structs
- Add server/remote tracking to `ServerState`
- Refactor channel membership to use `MemberId`
- Update existing handlers to use `MemberId::Local(id)` where they currently use `ClientId`

### Step 4: Server link — handshake
- `s2s/link.rs`: Accept inbound server connection on designated port
- Detect server connection (receives PASS + SERVER instead of NICK + USER)
- Parse SERVER message: extract name, numeric, timestamp, protocol version, flags
- Validate password against Connect block
- Send our PASS + SERVER response
- Transition to BURSTING state

### Step 5: Burst receive — process incoming state
- `s2s/burst.rs` + `s2s/handlers.rs`
- Handle `S` (SERVER): register remote servers in state
- Handle `N` (NICK): create RemoteClient, register in state
- Handle `B` (BURST): parse channel burst — create/update channels, add remote members with modes, process bans
- Handle `EB` (END_OF_BURST): mark link as burst-complete, send our burst + EA

### Step 6: Burst send — transmit our state
- Generate and send `S` messages for our server (just us, no downlinks yet)
- Generate and send `N` messages for all local users
- Generate and send `B` messages for all channels with local members
- Send `EB` to signal burst complete

### Step 7: Steady-state routing
- Route local PRIVMSG/NOTICE to remote via P10 `P`/`O` tokens
- Handle incoming `P`/`O` from remote — deliver to local channel members or private recipient
- Handle `J` (JOIN), `L` (PART), `Q` (QUIT), `K` (KICK), `T` (TOPIC) from remote — update state and notify local users
- Handle `M` (MODE) from remote — apply to channels/users
- Handle `N` (NICK change) from remote
- Handle `AC` (ACCOUNT) from remote — track account state on remote users
- Handle `C` (CREATE) and `DE` (DESTRUCT) for channel lifecycle

### Step 8: PING/PONG and SQUIT
- Handle `G` (PING) from remote — respond with `Z` (PONG)
- Send periodic PINGs to check link health
- Handle `SQ` (SQUIT) — clean up remote server + all its users/channels
- Handle connection drop — same as SQUIT but initiated locally

### Step 9: Config and compose integration
- Add Connect block to `data/ircd-rs.conf` (link to C nefarious)
- Add Connect block to `data/ircd.conf` (accept link from Rust server)
- Server port config (Port block with `server = yes`)
- Test end-to-end linking

## Critical Files to Modify

| File | Changes |
|------|---------|
| `Cargo.toml` (workspace) | Add `p10-proto` crate |
| `crates/p10-proto/` | New crate (all files) |
| `crates/nefarious/src/s2s/` | New module (all files) |
| `crates/nefarious/src/state.rs` | Add server/remote tracking, `MemberId` support |
| `crates/nefarious/src/channel.rs` | Refactor to `MemberId`, support remote members |
| `crates/nefarious/src/server.rs` | Accept server connections on server ports |
| `crates/nefarious/src/connection.rs` | Detect PASS+SERVER vs NICK+USER, route to S2S |
| `crates/nefarious/src/handlers/messaging.rs` | Route to S2S link for channel/private messages |
| `crates/nefarious/src/handlers/channel.rs` | Notify S2S link on JOIN/PART/TOPIC/KICK |
| `crates/nefarious/src/handlers/mode.rs` | Notify S2S link on MODE changes |
| `crates/nefarious/src/main.rs` | Add s2s module |
| `data/ircd-rs.conf` | Add server port + Connect block |
| `data/ircd.conf` | Add Connect block for nefarious-rs |

## Verification

1. **Unit tests**: P10 base64 encode/decode, message parsing, token mapping
2. **Integration**: Start both servers, verify link establishes:
   ```
   docker compose --profile rust up -d
   docker compose logs -f nefarious-rs
   ```
   Look for: handshake, burst received, EB/EA exchange
3. **Cross-server messaging**: Connect client A to C nefarious (port 6667), client B to Rust (port 6680). Both JOIN #test. Client A sends message — client B receives it, and vice versa.
4. **Nick visibility**: `/WHOIS remoteuser` on Rust server shows user from C server
5. **SQUIT**: Stop one server, verify the other cleans up remote users
6. **Channel state**: Channel modes, topic, bans from burst are correctly applied

## Key Protocol Details (Reference)

### Base64 Alphabet
```
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]
```

### Handshake Sequence
```
Rust→C:  PASS :serverlink123
Rust→C:  SERVER rs.fractalrealities.net 1 <start_ts> <link_ts> J10 <numeric_capacity> +6 :nefarious-rs
C→Rust:  PASS :serverlink123
C→Rust:  SERVER testnet.fractalrealities.net 1 <start_ts> <link_ts> J10 ABAAC +h6o :Nefarious IRCd
```

### Burst Message Examples
```
:AB S leaf.fractalrealities.net 2 0 <ts> J10 ABAAC +6 :Leaf
:AB N alice 1 <nick_ts> alice alice.host +i AAAAAA AB AAA :Alice
:AB B #test <create_ts> +nt ABAAB,ABAAC:o :%*!*@banned
:AB EB
```

### Token Quick Reference (Phase 1)
| Token | Command | Handler needed |
|-------|---------|----------------|
| PA | PASS | Handshake |
| S | SERVER | Handshake + burst |
| N | NICK | Burst + steady-state |
| B | BURST | Burst |
| EB | END_OF_BURST | Burst |
| EA | EOB_ACK | Burst |
| P | PRIVMSG | Routing |
| O | NOTICE | Routing |
| J | JOIN | Channel sync |
| L | PART | Channel sync |
| Q | QUIT | User cleanup |
| M | MODE | Channel/user sync |
| K | KICK | Channel sync |
| T | TOPIC | Channel sync |
| C | CREATE | Channel lifecycle |
| DE | DESTRUCT | Channel lifecycle |
| AC | ACCOUNT | Account tracking |
| G | PING | Keepalive |
| Z | PONG | Keepalive |
| SQ | SQUIT | Netsplit |
| D | KILL | User removal |

