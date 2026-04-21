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

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};

use irc_proto::Message;
use irc_proto::message::Tag;

use crate::capabilities::Capability;
use crate::client::Client;

/// Generate a fresh msgid suitable for the IRCv3 `msgid` tag.
///
/// Format: `<13-hex-ms-timestamp>-<6-hex-counter>`. The timestamp gives
/// natural cross-restart uniqueness plus rough lexicographic ordering;
/// the atomic counter guarantees uniqueness for events produced within
/// the same millisecond. 20 chars total, well under the 64-char limit
/// clients tend to assume.
///
/// Msgids must be locally unique (spec MUST) and should be network-unique
/// (spec SHOULD); the timestamp+counter combination satisfies the MUST
/// directly and the SHOULD probabilistically across mixed-clock nodes.
/// Cross-server prefixing (using our P10 numeric) is a refinement we can
/// add when S2S msgid propagation lands — right now msgids are local
/// only, so the server prefix isn't load-bearing.
pub fn generate_msgid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let ts = Utc::now().timestamp_millis() as u64;
    format!("{:013x}-{:06x}", ts, n & 0xFFFFFF)
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
    /// Build a SourceInfo with `time` = now and no account. Useful for
    /// events that don't have a user source (server notices, etc.).
    pub fn now() -> Self {
        Self {
            time: Utc::now(),
            account: None,
            msgid: generate_msgid(),
        }
    }

    /// Build from a local client: `time` = now, account pulled from
    /// the Client struct.
    pub fn from_local(client: &Client) -> Self {
        Self {
            time: Utc::now(),
            account: client.account.clone(),
            msgid: generate_msgid(),
        }
    }

    /// Build from a remote client: `time` = now (i.e. when we
    /// processed the s2s event), account pulled from the RemoteClient
    /// struct populated during P10 burst / ACCOUNT updates.
    pub fn from_remote(remote: &crate::s2s::types::RemoteClient) -> Self {
        Self {
            time: Utc::now(),
            account: remote.account.clone(),
            msgid: generate_msgid(),
        }
    }
}

/// Format a `DateTime<Utc>` as the IRCv3 `server-time` tag value.
///
/// Per the spec this is ISO 8601 with millisecond precision and a
/// trailing `Z` for UTC.
pub fn format_server_time(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
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
        // Format check: 13 hex, dash, 6 hex.
        assert!(a.len() == 20, "unexpected msgid length: {a}");
        let (ts, ctr) = a.split_once('-').expect("msgid should contain '-'");
        assert_eq!(ts.len(), 13);
        assert_eq!(ctr.len(), 6);
        u64::from_str_radix(ts, 16).expect("timestamp half must be hex");
        u64::from_str_radix(ctr, 16).expect("counter half must be hex");
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
