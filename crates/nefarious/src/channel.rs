use std::collections::{HashMap, HashSet};

use irc_proto::irc_casefold;
use p10_proto::ClientNumeric;

use crate::client::ClientId;

/// Membership flags for a user in a channel.
#[derive(Debug, Clone, Default)]
pub struct MembershipFlags {
    pub op: bool,
    pub voice: bool,
}

impl MembershipFlags {
    /// Prefix character for NAMES reply.
    pub fn highest_prefix(&self) -> &str {
        if self.op {
            "@"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }
}

/// Channel modes as a struct.
#[derive(Debug, Clone, Default)]
pub struct ChannelModes {
    /// +n: no external messages
    pub no_external: bool,
    /// +t: topic settable by ops only
    pub topic_ops_only: bool,
    /// +m: moderated
    pub moderated: bool,
    /// +i: invite only
    pub invite_only: bool,
    /// +s: secret
    pub secret: bool,
    /// +p: private
    pub private: bool,
    /// +k: key (password)
    pub key: Option<String>,
    /// +l: user limit
    pub limit: Option<u32>,
}

impl ChannelModes {
    /// Format as a mode string (e.g., "+ntk secret").
    pub fn to_mode_string(&self) -> String {
        let mut modes = String::from("+");
        let mut params = Vec::new();

        if self.no_external {
            modes.push('n');
        }
        if self.topic_ops_only {
            modes.push('t');
        }
        if self.moderated {
            modes.push('m');
        }
        if self.invite_only {
            modes.push('i');
        }
        if self.secret {
            modes.push('s');
        }
        if self.private {
            modes.push('p');
        }
        if let Some(ref key) = self.key {
            modes.push('k');
            params.push(key.clone());
        }
        if let Some(limit) = self.limit {
            modes.push('l');
            params.push(limit.to_string());
        }

        if modes.len() == 1 {
            // Just "+" with no modes
            return "+".to_string();
        }

        if params.is_empty() {
            modes
        } else {
            format!("{} {}", modes, params.join(" "))
        }
    }
}

/// An IRC channel.
#[derive(Debug)]
pub struct Channel {
    /// Channel name (including prefix, e.g., "#test").
    pub name: String,
    /// Topic text.
    pub topic: Option<String>,
    /// Who set the topic.
    pub topic_setter: Option<String>,
    /// When the topic was set.
    pub topic_time: Option<chrono::DateTime<chrono::Utc>>,
    /// Channel modes.
    pub modes: ChannelModes,
    /// Local members: ClientId → membership flags.
    pub members: HashMap<ClientId, MembershipFlags>,
    /// Remote members: ClientNumeric → membership flags (from P10 burst/JOIN).
    pub remote_members: HashMap<ClientNumeric, MembershipFlags>,
    /// Ban list.
    pub bans: Vec<BanEntry>,
    /// Creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Creation timestamp as epoch seconds (for P10 burst).
    pub created_ts: u64,
    /// Invited users (by client ID, cleared on join).
    pub invites: HashSet<ClientId>,
}

#[derive(Debug, Clone)]
pub struct BanEntry {
    pub mask: String,
    pub set_by: String,
    pub set_at: chrono::DateTime<chrono::Utc>,
}

impl Channel {
    pub fn new(name: String) -> Self {
        let now = chrono::Utc::now();
        Self {
            name,
            topic: None,
            topic_setter: None,
            topic_time: None,
            modes: ChannelModes {
                no_external: true,
                topic_ops_only: true,
                ..Default::default()
            },
            members: HashMap::new(),
            remote_members: HashMap::new(),
            bans: Vec::new(),
            created_at: now,
            created_ts: now.timestamp() as u64,
            invites: HashSet::new(),
        }
    }

    /// Add a member to the channel.
    pub fn add_member(&mut self, id: ClientId, flags: MembershipFlags) {
        self.invites.remove(&id);
        self.members.insert(id, flags);
    }

    /// Remove a member from the channel.
    pub fn remove_member(&mut self, id: &ClientId) {
        self.members.remove(id);
    }

    /// Check if a client is a member.
    pub fn is_member(&self, id: &ClientId) -> bool {
        self.members.contains_key(id)
    }

    /// Check if a client is an operator.
    pub fn is_op(&self, id: &ClientId) -> bool {
        self.members.get(id).is_some_and(|f| f.op)
    }

    /// Check if a client has voice.
    pub fn has_voice(&self, id: &ClientId) -> bool {
        self.members.get(id).is_some_and(|f| f.voice)
    }

    /// Check if the channel is empty (no local or remote members).
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.remote_members.is_empty()
    }

    /// Total member count (local + remote).
    pub fn total_members(&self) -> usize {
        self.members.len() + self.remote_members.len()
    }

    /// Check if a client can send to this channel.
    pub fn can_send(&self, id: &ClientId) -> bool {
        if !self.modes.no_external && !self.is_member(id) {
            // External messages allowed and not a member
            return true;
        }
        if !self.is_member(id) {
            return !self.modes.no_external;
        }
        if self.modes.moderated {
            return self.is_op(id) || self.has_voice(id);
        }
        true
    }

    /// Check if a user matches any ban mask.
    pub fn is_banned(&self, prefix: &str) -> bool {
        self.bans
            .iter()
            .any(|b| wildcard_match(&b.mask, prefix))
    }

    /// Check if a user can join this channel.
    pub fn can_join(&self, id: &ClientId, prefix: &str, key: Option<&str>) -> JoinCheck {
        if self.is_member(id) {
            return JoinCheck::AlreadyMember;
        }
        if self.invites.contains(id) {
            return JoinCheck::Ok;
        }
        if self.is_banned(prefix) {
            return JoinCheck::Banned;
        }
        if self.modes.invite_only {
            return JoinCheck::InviteOnly;
        }
        if let Some(ref chan_key) = self.modes.key {
            if key != Some(chan_key.as_str()) {
                return JoinCheck::BadKey;
            }
        }
        if let Some(limit) = self.modes.limit {
            if self.members.len() as u32 >= limit {
                return JoinCheck::Full;
            }
        }
        JoinCheck::Ok
    }
}

#[derive(Debug, PartialEq)]
pub enum JoinCheck {
    Ok,
    AlreadyMember,
    Banned,
    InviteOnly,
    BadKey,
    Full,
}

/// Simple IRC wildcard matching (* and ?), rfc1459-case-insensitive.
fn wildcard_match(pattern: &str, input: &str) -> bool {
    let pattern = irc_casefold(pattern);
    let input = irc_casefold(input);
    wildcard_match_inner(pattern.as_bytes(), input.as_bytes())
}

fn wildcard_match_inner(pattern: &[u8], input: &[u8]) -> bool {
    match (pattern.first(), input.first()) {
        (None, None) => true,
        (Some(b'*'), _) => {
            // Try matching * against zero chars, or consuming one input char
            wildcard_match_inner(&pattern[1..], input)
                || (!input.is_empty() && wildcard_match_inner(pattern, &input[1..]))
        }
        (Some(b'?'), Some(_)) => wildcard_match_inner(&pattern[1..], &input[1..]),
        (Some(p), Some(i)) if p == i => wildcard_match_inner(&pattern[1..], &input[1..]),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcard_basic() {
        assert!(wildcard_match("*!*@*", "nick!user@host"));
        assert!(wildcard_match("nick!*@*", "nick!user@host"));
        assert!(!wildcard_match("other!*@*", "nick!user@host"));
        assert!(wildcard_match("*!*@*.example.com", "nick!user@foo.example.com"));
    }

    #[test]
    fn mode_string() {
        let modes = ChannelModes {
            no_external: true,
            topic_ops_only: true,
            ..Default::default()
        };
        assert_eq!(modes.to_mode_string(), "+nt");
    }

    #[test]
    fn mode_string_with_params() {
        let modes = ChannelModes {
            no_external: true,
            key: Some("secret".into()),
            limit: Some(50),
            ..Default::default()
        };
        assert_eq!(modes.to_mode_string(), "+nkl secret 50");
    }
}
