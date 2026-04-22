//! Per-recipient IRCv3 tag injection.
//!
//! Outgoing broadcast messages (PRIVMSG, NOTICE, JOIN, PART, …) are
//! constructed once at the originating handler and then cloned to
//! each recipient. Which tags get attached depends on the *recipient*'s
//! negotiated capabilities, not the sender's — a channel with three
//! members at different CAP levels should produce three different wire
//! lines.
//!
//! `SourceInfo` captures the event metadata we need at recipient-send
//! time (the event timestamp for `server-time`, the source user's
//! account for `account-tag`, the per-event msgid for the IRCv3
//! `msgid` spec). Call sites build one `SourceInfo` per broadcast and
//! pass it to `Client::send_from`, which applies the cap-gated tags
//! for that specific recipient. `msgid` is allocated once in the
//! constructor so every recipient of a given event sees the same
//! value (per the IRCv3 spec — the ID identifies the event, not the
//! delivery).

use std::sync::{Mutex, OnceLock};

use chrono::{DateTime, Utc};

use irc_proto::Message;
use irc_proto::message::Tag;

use crate::capabilities::Capability;
use crate::client::Client;

/// Our server's 2-char P10 base64 YY numeric, set once at startup by
/// `init_hlc`. `generate_msgid` reads it to prefix every msgid so the
/// 14-char compact form is globally unique across the network.
static SERVER_YY: OnceLock<String> = OnceLock::new();

/// Hybrid Logical Clock state (Kulkarni et al. 2014). Pairs a wall-
/// clock millisecond count with a 16-bit logical counter to produce
/// network-wide causally-ordered event ids, even with skew and
/// restarts. Matches nefarious2's `struct HLC` in
/// `include/crdt_hlc.h`.
///
/// - `physical_ms` — the largest epoch-ms we've observed. On a local
///   event, bumped to `max(physical_ms, now)`. On receive, bumped to
///   `max(physical_ms, remote_ms, now)`.
/// - `logical` — bumped on same-ms events so ids stay unique and the
///   `(physical_ms, logical)` pair is monotone. Resets to 0 when
///   `physical_ms` advances.
/// - `msgid_counter` — global 54-bit monotonic counter for the `Q`
///   field of the msgid. Seeded from wall-clock ms at startup so it
///   keeps advancing across server restarts (no counter resets that
///   could alias against in-flight ids from a previous generation).
struct Hlc {
    physical_ms: u64,
    logical: u16,
    msgid_counter: u64,
}

static HLC: OnceLock<Mutex<Hlc>> = OnceLock::new();

fn wall_clock_ms() -> u64 {
    Utc::now().timestamp_millis() as u64
}

/// Initialise the HLC and YY prefix at server startup. Must be called
/// once before any event can build a SourceInfo. Subsequent calls are
/// no-ops (OnceLock semantics).
pub fn init_hlc(numeric: p10_proto::ServerNumeric) {
    let _ = SERVER_YY.set(numeric.to_string());
    let now = wall_clock_ms();
    let _ = HLC.set(Mutex::new(Hlc {
        physical_ms: now,
        logical: 0,
        msgid_counter: now,
    }));
}

/// Lazy HLC accessor. Production code calls `init_hlc` at startup so
/// `SERVER_YY` gets the right value; tests (and any path that invokes
/// `generate_msgid` before init) get a zero-seeded default. The
/// absence of a real YY means msgids get the `__` fallback, which is
/// fine for correctness tests but not for wire use.
fn hlc() -> &'static Mutex<Hlc> {
    HLC.get_or_init(|| {
        let now = wall_clock_ms();
        Mutex::new(Hlc {
            physical_ms: now,
            logical: 0,
            msgid_counter: now,
        })
    })
}

/// Advance HLC for an originating local event. Returns
/// `(physical_ms, logical, counter)`. Mirrors nefarious2
/// `hlc_local_event` + `++MsgIdCounter` in `send.c:generate_msgid`.
fn hlc_local_event() -> (u64, u16, u64) {
    let mut hlc = hlc().lock().expect("HLC mutex poisoned");
    let now = wall_clock_ms();
    if now > hlc.physical_ms {
        hlc.physical_ms = now;
        hlc.logical = 0;
    } else {
        hlc.logical = hlc.logical.wrapping_add(1);
    }
    hlc.msgid_counter = hlc.msgid_counter.wrapping_add(1);
    (hlc.physical_ms, hlc.logical, hlc.msgid_counter)
}

/// Update HLC on receipt of a remote `(physical_ms, logical)`. Takes
/// `max(now, local.physical_ms, remote.physical_ms)` as the new
/// physical time; bumps `logical` accordingly so our next local id
/// sits strictly after the remote event we just observed. Mirrors
/// nefarious2 `hlc_global_receive`.
pub fn hlc_receive(remote_ms: u64, remote_logical: u16) {
    let mut hlc = hlc().lock().expect("HLC mutex poisoned");
    let now = wall_clock_ms();
    let max_ms = now.max(hlc.physical_ms).max(remote_ms);
    let next_logical = if max_ms == hlc.physical_ms && max_ms == remote_ms {
        hlc.logical.max(remote_logical).wrapping_add(1)
    } else if max_ms == hlc.physical_ms {
        hlc.logical.wrapping_add(1)
    } else if max_ms == remote_ms {
        remote_logical.wrapping_add(1)
    } else {
        0
    };
    hlc.physical_ms = max_ms;
    hlc.logical = next_logical;
}

/// Advance HLC for a local event and return the matching 14-char
/// compact msgid + the advanced physical_ms. The two values are
/// returned together because the `@time` on the S2S wire must reflect
/// the HLC's state *after* the advance that produced the msgid —
/// any separate `Utc::now()` call afterwards risks drifting.
///
/// Wire layout: `<YY_2><logical_3><counter_9>` — matches
/// nefarious2 `generate_msgid` in `ircd/send.c`.
fn generate_msgid_with_time() -> (u64, String) {
    let (ms, logical, counter) = hlc_local_event();
    // Fallback `AA` (P10 numeric 0) for test / pre-init paths —
    // stays within the base64 alphabet so the 14-char msgid parses
    // anywhere. Real deployments always set SERVER_YY via init_hlc.
    let yy = SERVER_YY.get().map(|s| s.as_str()).unwrap_or("AA");
    let msgid = format!(
        "{yy}{}{}",
        p10_proto::inttobase64_64(logical as u64, 3),
        p10_proto::inttobase64_64(counter, 9),
    );
    (ms, msgid)
}

/// Convenience for callers that only need the msgid (UI-side tagging
/// where we already track the event time separately). Currently only
/// exercised by tests — production paths always want the paired time
/// via `SourceInfo`.
#[cfg(test)]
fn generate_msgid() -> String {
    generate_msgid_with_time().1
}

/// Event metadata needed by IRCv3 tag attachment.
///
/// * `time` is when the event happened from our perspective (either
///   when a local client sent it or when we received a remote event).
/// * `account` is the source user's account name (`None` if not logged
///   in or source is a server).
/// * `msgid` uniquely identifies this event across the network; all
///   recipients of the same broadcast see the same value.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub time: DateTime<Utc>,
    pub account: Option<String>,
    pub msgid: String,
}

impl SourceInfo {
    /// Internal: build a SourceInfo with `time` and `msgid` taken
    /// from the same HLC advance, so the two always agree on the
    /// wire. Any constructor that represents an "originating here"
    /// event should route through this.
    fn fresh(account: Option<String>) -> Self {
        let (ms, msgid) = generate_msgid_with_time();
        // The HLC stores physical_ms which is always an epoch-ms in
        // the valid range; from_timestamp_millis only fails on
        // implausibly-distant values. Fall back to Utc::now on the
        // near-impossible overflow case.
        let time = DateTime::from_timestamp_millis(ms as i64).unwrap_or_else(Utc::now);
        Self { time, account, msgid }
    }

    /// Build a SourceInfo with `time` = HLC-advanced now and no
    /// account. Useful for events that don't have a user source
    /// (server notices, etc.).
    pub fn now() -> Self {
        Self::fresh(None)
    }

    /// Build from a local client: `time` = HLC-advanced now, account
    /// pulled from the Client struct.
    pub fn from_local(client: &Client) -> Self {
        Self::fresh(client.account.clone())
    }

    /// Build from a remote client: default to an HLC-advanced now;
    /// callers should chain `.with_inbound_tags(msg)` so the
    /// network-originated time+msgid overrides ours and we relay the
    /// same ids the upstream server put on the wire.
    pub fn from_remote(remote: &crate::s2s::types::RemoteClient) -> Self {
        Self::fresh(remote.account.clone())
    }

    /// Override `time` / `msgid` from a parsed inbound P10 message's
    /// tag block, when present. Preserves network-wide msgid
    /// consistency: a PRIVMSG we relay to local clients carries the
    /// *same* `@msgid` the originating server put on the wire, not
    /// a fresh one we'd generate locally. Intended as a fluent
    /// chain on top of `from_remote`:
    ///
    /// ```ignore
    /// let src = SourceInfo::from_remote(&rc).with_inbound_tags(msg);
    /// ```
    pub fn with_inbound_tags(mut self, msg: &p10_proto::P10Message) -> Self {
        if let Some(ms) = msg.tag_time_ms {
            if let Some(dt) = DateTime::from_timestamp_millis(ms as i64) {
                self.time = dt;
            }
        }
        if let Some(ref mid) = msg.tag_msgid {
            self.msgid = mid.clone();
        }
        self
    }
}

/// Format a `DateTime<Utc>` as the IRCv3 `server-time` tag value.
///
/// Per the spec this is ISO 8601 with millisecond precision and a
/// trailing `Z` for UTC.
pub fn format_server_time(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Build the compact P10 S2S tag prefix `@A<time_7><msgid_14>` for a
/// given event. Every `route_*` that propagates a user-visible event
/// should prepend this so peers broadcast the same `@time`/`@msgid`
/// to their own clients — preserves network-wide id consistency per
/// IRCv3 msgid.
///
/// Returns a string with no trailing space; callers concatenate with
/// `" "` before the origin numeric.
pub fn compact_s2s_tag_prefix(src: &SourceInfo) -> String {
    let time_ms = src.time.timestamp_millis() as u64;
    format!(
        "@A{}{}",
        p10_proto::inttobase64_64(time_ms, 7),
        src.msgid
    )
}

/// Apply cap-gated tags to `msg` for delivery to `recipient`, based on
/// `src`. Only modifies `msg` when at least one of the recipient's
/// active caps demands the tag. The returned message is ready to
/// hand to `recipient.send`.
pub fn tagged_for(mut msg: Message, recipient: &Client, src: &SourceInfo) -> Message {
    if recipient.has_cap(Capability::ServerTime) {
        msg.tags.push(Tag {
            key: "time".to_string(),
            value: Some(format_server_time(src.time)),
        });
    }
    if recipient.has_cap(Capability::AccountTag) {
        if let Some(ref acct) = src.account {
            msg.tags.push(Tag {
                key: "account".to_string(),
                value: Some(acct.clone()),
            });
        }
    }
    // `msgid` is gated on `message-tags`: per the IRCv3 msgid spec a
    // server MUST NOT send the tag to a client that hasn't negotiated
    // that cap. It applies to broadcastable events (PRIVMSG, NOTICE,
    // TAGMSG, JOIN/PART/QUIT/NICK/KICK/MODE/TOPIC) — essentially
    // anything a client might pin into chathistory — and we build a
    // SourceInfo for exactly those events, so unconditional emission
    // here is correct.
    if recipient.has_cap(Capability::MessageTags) {
        msg.tags.push(Tag {
            key: "msgid".to_string(),
            value: Some(src.msgid.clone()),
        });
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_time_tag_format_has_millis_and_z() {
        let ts = DateTime::parse_from_rfc3339("2026-04-20T12:34:56.789Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(format_server_time(ts), "2026-04-20T12:34:56.789Z");
    }

    #[test]
    fn generate_msgid_is_unique() {
        let a = generate_msgid();
        let b = generate_msgid();
        assert_ne!(a, b);
        // Compact P10 form: exactly 14 P10 base64 chars (YY + logical + counter).
        assert_eq!(a.len(), 14, "unexpected msgid length: {a}");
        for c in a.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '[' || c == ']',
                "msgid char {c:?} outside P10 base64 alphabet"
            );
        }
    }

    #[test]
    fn source_info_msgid_is_stable_within_one_event() {
        let a = SourceInfo::now();
        let cloned = a.clone();
        // A single event keeps its msgid across recipients; cloning the
        // SourceInfo (which is how handlers fan a broadcast out) preserves
        // it so every tagged_for call on that event emits the same ID.
        assert_eq!(a.msgid, cloned.msgid);
    }
}
