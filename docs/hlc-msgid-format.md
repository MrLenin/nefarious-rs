# HLC-based Msgid Format (v0 / `@A`)

**Status**: ✅ Implemented. Supersedes the `creation_epoch+counter` sketch in [wild-frolicking-mango.md](wild-frolicking-mango.md). Extracted from the shipping code in `nefarious/`.

## Why HLC

Independent msgid generation per server produces fragmented IDs (`A-<startup>-<counter>` vs `B-<startup>-<counter>`) for the same message, which forces semantic dedup in federated chathistory. A Hybrid Logical Clock (Kulkarni et al. 2014) gives causal ordering across servers even with skew, and its `(physical_ms, logical, node_id)` triple slots naturally into a fixed-width msgid: the same logical tick value appears in both endpoints' state, so derived IDs align and exact-match dedup works.

HLC also keeps `@time` honest — on receive, the local clock takes `max(now, local, remote)`, so replayed events never regress local time even when wall clocks drift.

## Wire Format

```
@A<time:7><msgid:14> <P10_message>
 │└─time─┘└─YY─┘└L─┘└Q────────┘
 │                              
 └─version byte ('A' = v0)
```

22 chars of tag overhead + 1 space + `@`. Parser auto-detects against the verbose `key=value` form by scanning for `=` between `@` and the first space — P10 base64 never contains `=`, so the test is unambiguous.

### Fields

| Field      | Chars | Encoding                           | Range / Source                              |
|------------|-------|------------------------------------|---------------------------------------------|
| `@`        | 1     | literal                            | tag prefix                                  |
| version    | 1     | P10 base64                         | `A` = v0                                    |
| time       | 7     | `inttobase64_64` of epoch_ms       | 42 bits → year ~2109                        |
| `YY`       | 2     | server numeric (`cli_yxx(&me)`)    | HLC `node_id` (uint16, tiebreaker)          |
| `LLL`      | 3     | `inttobase64_64` of HLC.logical    | 18 b64 bits hold the full uint16 logical    |
| `QQQQQQQQQ`| 9     | `inttobase64_64` of `++MsgIdCounter` | 54 bits, seeded from `hlc_wall_clock_ms()` at startup |

Msgid total: 14 chars. Same width as the pre-HLC compact sketch, but the middle+tail split changed from `EEEEEE/QQQQQQ` (creation epoch + 6-char counter) to `LLL/QQQQQQQQQ` (HLC logical + 9-char counter). `QQQQQQQQQ` being seeded from wall clock at init gives uniqueness across restarts even without the creation-epoch field.

### Time Field

Written from `hlc_global()->physical_ms` **after** `generate_msgid()` has advanced the HLC for that event — the msgid is generated first on purpose so the `@time` reflects the advanced clock, keeping `time` monotonic with msgid generation.

## HLC Primitive

Definition in [nefarious/include/crdt_hlc.h](../../nefarious/include/crdt_hlc.h):

```c
struct HLC {
    uint64_t physical_ms;   /* Wall clock milliseconds (epoch) */
    uint16_t logical;       /* Counter for same-ms events */
    uint16_t node_id;       /* Server numeric (tiebreaker) */
};
```

Core operations in [crdt_hlc.c](../../nefarious/ircd/crdt_hlc.c):

- `hlc_local_event(local)` — advance for an originating event. If wall clock > `physical_ms`, set `physical_ms = now` and reset `logical = 0`; else bump `logical`.
- `hlc_receive(local, remote)` — update on inbound. Standard HLC rule: `physical_ms = max(now, local.physical_ms, remote.physical_ms)`, `logical` derived from whichever was max (or max-of-both + 1 on tie).
- `hlc_compare(a, b)` — lexicographic on `(physical_ms, logical, node_id)`.

Overflow: `logical` is `uint16_t` (max 65535). Overflow logs a warning and wraps to 0 — 65k events in one ms is unrealistic for IRC.

Global state: `hlc_init(node_id)` in [ircd.c:1089](../../nefarious/ircd/ircd.c) seeds the server-wide clock using `(uint16_t)base64toint(cli_yxx(&me))`. `MsgIdCounter` gets seeded from `hlc_wall_clock_ms()` at the same point so it's monotonic across restarts.

## Generation (Local)

[send.c:381](../../nefarious/ircd/send.c):

```c
char *generate_msgid(char *buf, size_t buflen)
{
  struct HLC hlc = hlc_global_event();
  char logical_b64[4], counter_b64[10];
  inttobase64_64(logical_b64, (uint64_t)hlc.logical, 3);
  inttobase64_64(counter_b64, (uint64_t)(++MsgIdCounter), 9);
  snprintf(buf, buflen, "%s%s%s", cli_yxx(&me), logical_b64, counter_b64);
  return buf;
}
```

S2S tag assembly in `format_s2s_tags()` picks the msgid with this priority:
1. Preserved from inbound (`cli_s2s_msgid(cptr)` — originating server's msgid, kept intact)
2. Explicit override (`s2s_msgid_override`, used for forwarded commands)
3. Freshly generated via `generate_msgid()`

Then writes `@A<time_7><msgid_14> ` with time from `hlc_global()->physical_ms` after generation.

## Receive (Remote)

[parse.c:1702](../../nefarious/ircd/parse.c) — format detection + HLC update:

```c
if (!memchr(ch + 1, '=', tagend - ch - 1)) {
  /* COMPACT: @A<time:7><msgid:14> */
  if (tag_len >= 22 && ch[1] == 'A') {
    /* decode time (7 b64) -> cli_s2s_time_ms */
    /* copy msgid (14 chars) -> cli_s2s_msgid */
    /* decode logical (ch+9+2, 3 b64) + node_id (ch+9, 2 b64) + physical_ms */
    hlc_global_receive(&remote_hlc);
  }
} else {
  /* VERBOSE: key=value, backward-compat path for legacy peers */
}
```

`cli_s2s_msgid` / `cli_s2s_time_ms` on the *connection* (not the sender) carry the extracted tag to command handlers, which then either echo it in replies (labeled-response correlation) or use it to preserve origin IDs when re-broadcasting.

Buffers: `S2S_MSGID_BUFSIZE = 64` (wide enough for verbose `A-<epoch>-<counter>` *and* compact 14-char), `S2S_MULTI_MSGID_BUFSIZE = 256`.

## Multi-msgid (Batched CREATE/PART)

One S2S command can carry multiple channels. The tag encodes one msgid per channel, `+`-separated:

```
@A<time:7><msgid1>+<msgid2>+... <P10_command>
```

Built in [channel.c:5466](../../nefarious/ircd/channel.c) during joinbuf flush. Legacy parsers extract only the first 14 chars; the multi-msgid parser extracts the full `+`-separated list into `cli_s2s_multi_msgid` so [m_create.c:151](../../nefarious/ircd/m_create.c) and [m_part.c:242](../../nefarious/ircd/m_part.c) can match msgid[i] to channel[i].

## Derived Msgids (QUIT)

QUIT is 1:N — one S2S message, N channel history entries. The S2S tag carries one **base** msgid; each server derives the same per-channel ID deterministically. [s_misc.c:195](../../nefarious/ircd/s_misc.c):

```c
/* FNV-1a hash of channel name (case-insensitive), 6 b64 chars appended */
derived = base_msgid || inttobase64(fnv1a(lower(channel)), 6)
```

Result is a 20-char msgid. Birthday collision at 1000 channels ≈ 10⁻⁴.

## Why `A` and not `B`

The [CRDT mesh proposal](../../docs/proposals/crdt-mesh-s2s-protocol.md) sketched a version bump `A → B` when moving from `creation_epoch+counter` to HLC. Implementation chose to **replace v0 in place** instead: same version byte, same total width, different interior split. Rationale:
- The pre-HLC compact format was never deployed on a production link — no wire compatibility debt to carry.
- Keeping `@A` preserves a single parsing path and avoids a dead version byte.
- The receive-side parser only needs `YY + logical` for HLC, so the interior layout change is invisible to anything that doesn't peer into msgid bytes.

If a future format needs a real bump (e.g. wider logical, CRDT-mesh specific fields), it takes `B`.

## Files

Primary:
- [nefarious/include/crdt_hlc.h](../../nefarious/include/crdt_hlc.h) — HLC struct + API
- [nefarious/ircd/crdt_hlc.c](../../nefarious/ircd/crdt_hlc.c) — HLC implementation (Kulkarni 2014)
- [nefarious/ircd/send.c:381](../../nefarious/ircd/send.c) — `generate_msgid()`
- [nefarious/ircd/send.c:422](../../nefarious/ircd/send.c) — `format_s2s_tags()` (wire emit)
- [nefarious/ircd/parse.c:1702](../../nefarious/ircd/parse.c) — compact/verbose auto-detect + `hlc_global_receive()`
- [nefarious/ircd/ircd.c:1089](../../nefarious/ircd/ircd.c) — `hlc_init()` at startup, `MsgIdCounter` seed

Support:
- [nefarious/include/client.h:392](../../nefarious/include/client.h) — `S2S_MSGID_BUFSIZE`, `S2S_MULTI_MSGID_BUFSIZE`, connection fields
- [nefarious/ircd/channel.c:5466](../../nefarious/ircd/channel.c) — multi-msgid tag build for joinbuf
- [nefarious/ircd/s_misc.c:195](../../nefarious/ircd/s_misc.c) — `derive_channel_msgid()` (QUIT)
- [nefarious/ircd/m_create.c:151](../../nefarious/ircd/m_create.c), [m_part.c:242](../../nefarious/ircd/m_part.c) — multi-msgid consumers

## Related

- [wild-frolicking-mango.md](wild-frolicking-mango.md) — original compact-tag plan (status stale re msgid interior layout; wire format + parser + derived-msgid sections remain accurate)
- [federation-dedup-s2s-msgid.md](federation-dedup-s2s-msgid.md) — msgid preservation through S2S relay (orthogonal, already shipped)
- [docs/proposals/crdt-mesh-s2s-protocol.md](../../docs/proposals/crdt-mesh-s2s-protocol.md) — where HLC msgids feed into the broader CRDT direction
