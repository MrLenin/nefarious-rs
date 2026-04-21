# Phase 2 — IRCv3 Capabilities

*Parallel to the roadmap's "Phase 2: IRCv3 Capabilities (4–6 weeks)". Parity target is the C branch's full capability list in [nefarious2/include/capab.h](https://github.com/MrLenin/nefarious2/blob/ircv3.2-upgrade/include/capab.h). This plan breaks Phase 2 into nine sub-phases sized for single commits, in dependency order.*

## Goal
Implement the widely-used, non-draft IRCv3 capabilities exactly as `nefarious2/ircv3.2-upgrade` exposes them: same cap names, same negotiation flow, same tag formats, same BATCH/labeled-response semantics. Draft caps and SASL mechanisms are deferred to Phase 3. Per the design rule, internal implementation is free to improve on C; the wire must stay identical.

## Non-goals for Phase 2
- SASL authentication mechanisms (PLAIN / EXTERNAL / SCRAM / OAUTHBEARER) — Phase 3.
- Any `draft/*` capability (`draft/chathistory`, `draft/multiline`, `draft/bouncer`, etc.) — Phase 3+ once the base is stable.
- `sts` / `tls` (already handled by the TLS listener logic; the cap is only advertised).

## Cap inventory vs parity
| C cap | Phase | Notes |
|---|---|---|
| `cap-notify` | 2.1 | foundational — enables CAP NEW/DEL after registration |
| `message-tags` | 2.2 | parser already handles, needs forwarding |
| `server-time` | 2.2 | `@time=` on outbound |
| `account-tag` | 2.2 | `@account=` on outbound |
| `echo-message` | 2.3 | reflect PRIVMSG/NOTICE |
| `batch` | 2.4 | framing for labeled-response, future history |
| `labeled-response` | 2.4 | pairs with `batch` |
| `multi-prefix` | 2.5 | NAMES / WHO formatting |
| `userhost-in-names` | 2.5 | NAMES formatting |
| `invite-notify` | 2.6 | broadcast INVITE to channel ops |
| `away-notify` | 2.6 | AWAY state to subscribed clients |
| `standard-replies` | 2.6 | FAIL/WARN/NOTE emission framework |
| `chghost` | 2.6 | command + broadcast |
| `setname` | 2.6 | command + broadcast |
| `account-notify` | 2.7 | ACCOUNT broadcast (stub-able until Phase 3 SASL) |
| `extended-join` | 2.7 | JOIN with account+realname |
| `sasl` | 2.8 | negotiation surface only; mechanisms in Phase 3 |
| all `draft/*` | — | deferred |

---

## 2.1 — CAP negotiation framework
**Scope (wire):** `CAP LS 302`, `CAP REQ`, `CAP ACK`/`NAK`, `CAP LIST`, `CAP END`, post-registration `CAP NEW`/`DEL` (emitted only; clients with `cap-notify` receive them when the advertised set changes).

**Data model:**
- `Capability` enum mirroring C's `enum Capab` (same identifiers, same names).
- `Client.advertised_caps: CapSet`, `Client.enabled_caps: CapSet`.
- `Client.cap_negotiating: bool` — set by CAP LS, cleared by CAP END; blocks registration while true.
- Server-level `advertised_caps` bitset, checked on REQ.
- CAP version parsing: treat `302` as the current supported version; accept a smaller number but fall back to v1 format (no value metadata after `=`).

**Acceptance:** `irssi` and `weechat` complete CAP LS / REQ / END and register successfully; unsupported REQ gets NAK; `CAP LIST` mid-session returns the enabled subset. No cap behaviours wired yet — the framework alone.

**Roughly:** ~300 lines (module + client fields + dispatch + registration gate). One commit.

## 2.2 — Message tags + server-time + account-tag
**Scope (wire):** preserve `@key=value` tags parsed on inbound messages; emit `@time=YYYY-MM-DDTHH:MM:SS.sssZ` on every outbound PRIVMSG/NOTICE/JOIN/PART/QUIT/KICK/MODE/NICK/TOPIC/INVITE to clients with `server-time`; emit `@account=<name>` when the source user has an account and the recipient has `account-tag`.

**Data model:**
- Extend the outbound message pipeline (Client::send) with a per-recipient "tag set" hook.
- Reuse existing `Tag` struct in `irc-proto/src/message.rs`; just need to produce tags at send time based on recipient caps.
- Server tag vs client tag (`+`-prefixed) handling in the codec.

**Acceptance:** a `server-time`-enabled client that receives a PRIVMSG sees the `@time` tag with millisecond precision matching the C server's output. A `account-tag`-enabled client sees `@account=alice` when alice is logged in. Clients without those caps see bare messages.

**Roughly:** ~200 lines. One commit.

## 2.3 — echo-message
**Scope (wire):** when a client with `echo-message` sends PRIVMSG or NOTICE, the server echoes the same message back to them with the expected tags (`time`, `label` if set, `account` if applicable).

**Data model:** no new state; adds an early branch in the messaging handler.

**Acceptance:** a client in the same session sees their own PRIVMSG back on their socket, with source=their prefix. C's behaviour matches byte-for-byte.

**Roughly:** ~50 lines. Tiny commit — good validation that 2.2 works.

## 2.4 — batch + labeled-response
**Scope (wire):**
- Generic BATCH framework: `BATCH +<id> <type> [params]` / `BATCH -<id>`. Nested batches supported.
- Inbound `@label=<n>` on a command → all response messages generated in handling that command get `@label=<n>` and are wrapped in a `labeled-response` batch. Single-line responses may skip the batch and carry the label inline (per spec).

**Data model:**
- `HandlerContext.current_label: Option<String>` set by dispatch, read by every `send_numeric`/`send` path.
- Per-client BATCH id counter.

**Acceptance:** `@label=abc PING :foo` returns `@label=abc PONG` (single-line path). `@label=abc WHOIS nick` returns `@batch=xyz ... END` with all WHOIS numerics tagged, wrapped by `BATCH +xyz labeled-response` / `BATCH -xyz`.

**Risk:** touches every response-emitting path. Mitigation — route all outbound through a single "emit" method that reads the label.

**Roughly:** ~250 lines plus churn. One commit.

## 2.5 — multi-prefix + userhost-in-names
**Scope (wire):**
- NAMES replies emit `@+nick` (all prefixes) instead of just highest prefix when the requester has `multi-prefix`.
- With `userhost-in-names`, the names include `@+nick!user@host`.
- WHO reply already shows one prefix; `multi-prefix` extends to full set.

**Data model:** no new state; formatting branches in `send_names` / `handle_who` keyed on the requester's cap set.

**Acceptance:** the `userhost-in-names` token in ISUPPORT is correct; a multi-prefix-enabled client sees `=@+alice` vs `=@alice` for an op+voiced user.

**Roughly:** ~80 lines. One commit.

## 2.6 — Notify-style caps and chghost/setname
**Scope (wire, five caps in one batch):**
- `away-notify` — when user X toggles AWAY, send `:X AWAY [:<msg>]` to every `away-notify` client sharing a channel with X.
- `invite-notify` — when X invites Y to #c, send `:X INVITE Y #c` to every `invite-notify` client on #c with op.
- `standard-replies` — `FAIL <cmd> <code> [<ctx>] :<desc>`, `WARN …`, `NOTE …`; add helpers to numeric module and rewrite a handful of existing error paths to also emit a FAIL when the recipient has the cap.
- `chghost` — new CHGHOST command (server/operator use): change user's host, broadcast `:old!user@old CHGHOST newuser newhost` to every `chghost` client sharing a channel.
- `setname` — new SETNAME command for self-realname change; broadcast `:prefix SETNAME :newname` to every `setname` client sharing a channel.

**Data model:** utility "broadcast to cap-subscribers sharing channel with X" helper in `ServerState`.

**Acceptance:** toggling AWAY with an away-notify client watching produces exactly the C wire output. Similarly for the other four.

**Roughly:** ~300 lines spread across handlers + state helpers. One commit, or split into 2.6a (away/invite/standard-replies) + 2.6b (chghost/setname) if it feels too chunky.

## 2.7 — account-notify + extended-join
**Scope (wire):**
- `extended-join` — JOIN includes `<account> :<realname>` params for the joiner, visible to extended-join clients only.
- `account-notify` — when a user's account changes (login/logout), broadcast `:X ACCOUNT <newname-or-*>` to account-notify clients sharing a channel.

**Data model:** `Client.account: Option<String>` (remote already has this). Populated temporarily by OPER for testing; real population arrives with SASL in Phase 3.

**Acceptance:** fake-opering a user and then testing JOIN output against extended-join produces the account field. account-notify broadcasts with `*` on logout.

**Dependency note:** the CAP negotiation and wire format are entirely self-contained; the actual "log a user in" side is a Phase 3 concern. Ship with a debug-only `TESTLOGIN` command if needed to exercise it, and remove it at the end of Phase 3.

**Roughly:** ~150 lines + a stub auth hook. One commit.

## 2.8 — sasl (negotiation only)
**Scope (wire):** advertise `sasl` with its mechanism list as metadata (`sasl=PLAIN,EXTERNAL`); accept `AUTHENTICATE <mechanism>` inbound; reject with an ERR_SASLFAIL equivalent until Phase 3 implements the mechanisms.

**Data model:** hook point for the Phase 3 handler.

**Acceptance:** `weechat` sees `sasl` advertised in CAP LS; issuing `AUTHENTICATE PLAIN` doesn't hang; negotiation ends cleanly with a standard FAIL.

**Roughly:** ~80 lines. One commit; real work follows in Phase 3.

## 2.9 — cap-notify + exit checks
**Scope (wire):** wire `CAP NEW`/`CAP DEL` to every `cap-notify` client whenever the advertised set mutates at runtime (e.g., SASL turning on after config reload, or a cap being toggled off). Also: regression test against nefarious2 to confirm parity with a scripted CAP LS dump.

**Data model:** global `advertised_caps` mutation entry point that emits the notifications.

**Acceptance:** we pipe nefarious-rs's full `CAP LS 302` output through `diff` against nefarious2's, plus a handful of REQ/ACK cycles. Zero divergences.

**Roughly:** ~60 lines + tests. One commit.

---

## Test strategy across the phase
- **Unit:** cap set parsing, tag formatting, label propagation, mechanism gating.
- **Protocol integration:** a small test harness that drives a TCP client through scripted CAP sequences and diffs against captured C output.
- **Live clients:** `weechat` + `irssi` run through the golden-path IRCv3 set (CAP negotiation, server-time, away-notify, extended-join).
- **S2S:** no cap is S2S-observable except `account-notify` / `account-tag` which ride on the P10 ACCOUNT token and rely on Phase 3 SASL. Phase 2 mixed-version network test is unchanged from Phase 1.

## Risks / open questions
1. **Tag-attachment architecture.** Right now outbound messages are `Message` → `Display`. Tags differ per recipient (different caps). Decision needed: clone-and-mutate per recipient, or a send helper that appends tags at encode time?
2. **Labeled-response plumbing.** Every numeric and every outbound send needs to know the current request's label. Need a per-handler context plumbed through, rather than ad-hoc. Invasive; might require its own refactor commit before 2.4.
3. **standard-replies coverage.** Every existing ERR_* path could in principle get a FAIL counterpart. Scoping rule: only emit FAIL for commands that didn't exist before IRCv3 (WEBIRC, SASL, etc.) unless a client has `standard-replies` — avoids noisy duplicate error emission.
4. **account-notify without SASL.** Phase 2.7 ships plumbing but no real account source. Option A: ship with TESTLOGIN debug command. Option B: defer 2.7 until Phase 3 lands PLAIN. A is faster, B is cleaner. Lean toward A.

## Estimated sizing
9 sub-phases × ~150 lines avg ≈ 1400 LOC + tests. Roughly matches the roadmap's 4–6 weeks on a solo schedule with S2S testing interleaved.

