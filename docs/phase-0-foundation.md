# Nefarious-RS Phase 0: Foundation Scaffolding

## Context

Nefarious IRCd is ~147K lines of C. We're starting a parallel Rust rewrite while the current C build goes into live testing. This phase creates a new repo with the minimal foundation: accept IRC connections, register users, join channels, chat. No P10/S2S, no persistence, no SASL — just a working single-server IRC daemon.

**Decisions locked in:**
- New git repo (`nefarious-rs`), added as submodule to testnet
- tokio async runtime
- tokio-openssl for TLS (cert compatibility with existing PEM files)
- `nom` parser for ircd.conf format (backward compatibility)
- MDBX deferred to Phase 4

## Deliverables

### 1. Project Scaffolding

Create `nefarious-rs/` repo with cargo workspace:

```
nefarious-rs/
├── Cargo.toml              # workspace root
├── Dockerfile
├── CLAUDE.md
├── crates/
│   ├── nefarious/          # main binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       └── main.rs
│   ├── irc-proto/          # IRC message parsing/serialization
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── message.rs  # IRC message struct
│   │       ├── codec.rs    # tokio-util Codec for line framing
│   │       └── command.rs  # command enum
│   └── irc-config/         # ircd.conf parser
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── parser.rs   # nom-based ircd.conf parser
├── config/
│   └── ircd.conf           # example/test config
```

**Why workspace:** Separating protocol and config parsing into crates keeps compilation incremental and lets us test parsing independently.

### 2. Core Dependencies

```toml
# workspace Cargo.toml
[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["codec"] }
tokio-openssl = "0.6"
openssl = "0.10"
nom = "7"
tracing = "0.1"
tracing-subscriber = "0.3"
bytes = "1"
dashmap = "6"
thiserror = "2"
```

### 3. irc-proto Crate

**message.rs** — Core IRC message struct:
```rust
pub struct Message {
    pub tags: Option<Tags>,        // IRCv3 message tags (parse but ignore for now)
    pub source: Option<String>,    // :prefix
    pub command: Command,
    pub params: Vec<String>,       // includes trailing
}
```

**codec.rs** — tokio-util `Codec` for IRC line framing:
- Lines delimited by `\r\n`
- Max line length 512 bytes (IRC limit), configurable
- Decode: bytes → `Message`
- Encode: `Message` → bytes

**command.rs** — Command enum covering Phase 0 commands:
- NICK, USER, PING, PONG, QUIT
- JOIN, PART, PRIVMSG, NOTICE, TOPIC, KICK
- MODE (basic)
- WHO, WHOIS, NAMES, LIST, MOTD
- CAP (stub — just reply with empty LS for now)

### 4. irc-config Crate

Minimal nom parser for ircd.conf block format:
```
BlockName {
    key = value;
    key = "string value";
    key = yes;
    flag;           # bare flag (e.g., hub;)
};
```

Phase 0 blocks to parse:
- **General** — name, description, numeric, vhost
- **Admin** — location, contact
- **Port** — port, ssl, websocket, server
- **Class** — name, pingfreq, sendq, maxlinks
- **Client** — class, ip, host, maxlinks, port
- **Operator** — name, host, password, class
- **Features** — key-value pairs

Time expressions: `1 minutes 30 seconds` → Duration

### 5. Server Core (nefarious crate)

**Architecture:**

```
main.rs
  → config loading
  → server startup

server.rs
  → bind listeners (Port blocks)
  → accept loop per listener
  → spawn connection task per client

connection.rs
  → per-client async task
  → registration state machine (UNREG → NICK → USER → REGISTERED)
  → framed read/write via irc-proto codec
  → TLS handshake (if SSL port)
  → dispatch registered commands

state.rs
  → ServerState (shared via Arc)
    - clients: DashMap<ClientId, Arc<Client>>
    - channels: DashMap<ChannelName, Arc<RwLock<Channel>>>
    - config: Arc<Config>
    - server_name: String
    - server_created: DateTime

client.rs
  → Client struct (nick, user, host, realname, modes, etc.)
  → writer channel (mpsc::Sender<Message>) for sending to this client

channel.rs
  → Channel struct (name, topic, modes, members)
  → Membership tracking
  → Basic modes: +o +v +m +n +t +i +k +l +s +p

handlers/
  → mod.rs (dispatch table: HashMap<Command, handler_fn>)
  → registration.rs (NICK, USER, CAP stub)
  → messaging.rs (PRIVMSG, NOTICE)
  → channel.rs (JOIN, PART, TOPIC, KICK, NAMES, LIST)
  → mode.rs (MODE — channel and user)
  → query.rs (WHO, WHOIS, MOTD)
  → connection.rs (PING, PONG, QUIT)

numeric.rs
  → Numeric reply constants (001-005, 353, 366, 401, 403, etc.)
  → ISUPPORT (005) generation
```

**Connection lifecycle:**
1. Accept TCP connection (plain or TLS based on listener)
2. Spawn async task with framed codec
3. Wait for NICK + USER (handle PING during registration)
4. Send 001-005 welcome + MOTD
5. Enter main message loop — read, dispatch, respond
6. On QUIT or disconnect — remove from channels, notify peers, cleanup

**Message routing:**
- PRIVMSG/NOTICE to channel → iterate members, send to each (except sender)
- PRIVMSG/NOTICE to nick → lookup in clients map, send directly
- JOIN → add to channel, notify existing members
- PART/QUIT → remove from channel, notify remaining members

### 6. Dockerfile

Multi-stage build:
1. `builder` — rust:1.87-bookworm, cargo build --release
2. `runtime` — debian:bookworm-slim, libssl3, copy binary

Mount config from testnet `data/` directory, reuse existing SSL certs.

### 7. Testnet Integration

Add to docker-compose.yml as a new service (e.g., `nefarious-rs`) with its own port mappings (e.g., 6680 plaintext, 6699 SSL) so it can run alongside the C version for comparison testing.

## Implementation Order

1. Create repo, Cargo.toml workspace, CLAUDE.md
2. irc-proto: Message struct, Codec, Command enum
3. irc-config: nom parser for ircd.conf (General, Port, Class, Client, Features)
4. Server: config loading, listener binding, TLS setup
5. Connection: registration state machine (NICK/USER), welcome burst
6. Handlers: PING/PONG, QUIT
7. State: client registry (DashMap)
8. Handlers: JOIN/PART, channel state, NAMES
9. Handlers: PRIVMSG/NOTICE (channel + private)
10. Handlers: TOPIC, KICK, MODE (basic)
11. Handlers: WHO, WHOIS, LIST, MOTD
12. Numeric replies and ISUPPORT
13. Dockerfile
14. Add as submodule + docker-compose service in testnet

## Verification

- Connect with irssi/weechat to plain and SSL ports
- Register (NICK/USER), receive welcome
- JOIN a channel, see NAMES reply
- PRIVMSG to channel from two clients — both receive
- PRIVMSG to nick — private message works
- PART, QUIT — other clients notified
- MODE +o, +v, +m, +t — basic channel modes work
- TOPIC — set and display
- KICK — remove user from channel
- WHO/WHOIS — return correct info
- MOTD — display message of the day
- TLS connections work with existing PEM certs

