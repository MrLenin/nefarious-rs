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
//! account for `account-tag`). Call sites build one `SourceInfo` per
//! broadcast and pass it to `Client::send_from`, which applies the
//! cap-gated tags for that specific recipient.

use chrono::{DateTime, Utc};

use irc_proto::Message;
use irc_proto::message::Tag;

use crate::capabilities::Capability;
use crate::client::Client;

/// Event metadata needed by IRCv3 tag attachment.
///
/// * `time` is when the event happened from our perspective (either
///   when a local client sent it or when we received a remote event).
/// * `account` is the source user's account name (`None` if not logged
///   in or source is a server).
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub time: DateTime<Utc>,
    pub account: Option<String>,
}

impl SourceInfo {
    /// Build a SourceInfo with `time` = now and no account. Useful for
    /// events that don't have a user source (server notices, etc.).
    pub fn now() -> Self {
        Self {
            time: Utc::now(),
            account: None,
        }
    }

    /// Build from a local client: `time` = now, account pulled from
    /// the Client struct.
    pub fn from_local(client: &Client) -> Self {
        Self {
            time: Utc::now(),
            account: client.account.clone(),
        }
    }

    /// Build from a remote client: `time` = now (i.e. when we
    /// processed the s2s event), account pulled from the RemoteClient
    /// struct populated during P10 burst / ACCOUNT updates.
    pub fn from_remote(remote: &crate::s2s::types::RemoteClient) -> Self {
        Self {
            time: Utc::now(),
            account: remote.account.clone(),
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
}
