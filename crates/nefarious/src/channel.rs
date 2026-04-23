use std::collections::{HashMap, HashSet};

use irc_proto::irc_casefold;
use p10_proto::ClientNumeric;

use crate::client::ClientId;

/// Membership flags for a user in a channel.
#[derive(Debug, Clone, Default)]
pub struct MembershipFlags {
    pub op: bool,
    pub halfop: bool,
    pub voice: bool,
    /// P10 oplevel (0..=999). `None` when the member is not an op, or
    /// when the peer did not advertise oplevel support (in which case
    /// we treat the op as MAXOPLEVEL-equivalent for dispatch).
    pub oplevel: Option<u16>,
}

impl MembershipFlags {
    /// Prefix character for NAMES reply.
    pub fn highest_prefix(&self) -> &str {
        if self.op {
            "@"
        } else if self.halfop {
            "%"
        } else if self.voice {
            "+"
        } else {
            ""
        }
    }

    /// All active prefixes in descending order of rank, for clients
    /// with the `multi-prefix` capability. When a user is both op and
    /// voice, we emit `@+` rather than the single highest prefix.
    pub fn all_prefixes(&self) -> String {
        let mut out = String::with_capacity(3);
        if self.op {
            out.push('@');
        }
        if self.halfop {
            out.push('%');
        }
        if self.voice {
            out.push('+');
        }
        out
    }
}

/// Channel modes as a struct.
///
/// The RFC1459 set (`+nt i m s p k l`) lives in dedicated fields with
/// enforcement logic. The nefarious2 extended set lives in
/// `extended_flags` as a set of chars — we track them for wire parity
/// so BURST / MODE / `to_mode_string` round-trip correctly across
/// peers, but most aren't enforced locally yet. Enforcement lands
/// per-feature as handlers need it.
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
    /// +L: redirect target on +i / +l overflow (channel name param)
    pub redirect: Option<String>,
    /// Extended nefarious2 channel modes that round-trip across S2S
    /// without local enforcement yet. Includes C/c/D/M/N/Q/R/r/S/T/
    /// u/z and any future parameterless flag we parse off the wire.
    /// Stored as chars so `to_mode_string` can emit in alphabetic
    /// order without hard-coding every known flag.
    pub extended_flags: std::collections::BTreeSet<char>,
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
        // Extended parameterless flags (C/c/D/M/N/Q/R/r/S/T/u/z)
        // emitted in BTreeSet order so the wire is deterministic.
        for c in &self.extended_flags {
            modes.push(*c);
        }
        if let Some(ref key) = self.key {
            modes.push('k');
            params.push(key.clone());
        }
        if let Some(limit) = self.limit {
            modes.push('l');
            params.push(limit.to_string());
        }
        if let Some(ref redir) = self.redirect {
            modes.push('L');
            params.push(redir.clone());
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
    /// Ban exception list (nefarious2 +e).
    pub excepts: Vec<BanEntry>,
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
            excepts: Vec::new(),
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

    /// Check if a client can send to this channel.
    pub fn can_send(&self, id: &ClientId, is_account: bool) -> bool {
        // +R / +M — registered-only speech gates. +R blocks all
        // speech (internal and external) from non-authenticated
        // users; +M is the less-strict variant that only blocks the
        // external-message path. Check both early so the existing
        // +n / +m logic doesn't override them.
        if self.modes.extended_flags.contains(&'R') && !is_account {
            return false;
        }
        if self.modes.extended_flags.contains(&'M') && !is_account && !self.is_member(id) {
            return false;
        }
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

    /// Content-aware send check. Layered on top of `can_send` and
    /// applied per-message to filter things like CTCP, NOTICEs, or
    /// colour codes based on the extended-flag mode set. Returns
    /// `Err(reason)` when the message should be refused with an
    /// explanatory 404, `Ok(())` otherwise. Ops bypass all
    /// content-level filters, matching nefarious2 channel.c's
    /// chanop-exempt policy so moderators can always speak.
    pub fn check_content(&self, id: &ClientId, is_notice: bool, text: &str) -> Result<(), &'static str> {
        if self.is_op(id) {
            return Ok(());
        }
        // +N — no channel NOTICEs.
        if is_notice && self.modes.extended_flags.contains(&'N') {
            return Err("Notices are not permitted on this channel (+N)");
        }
        // +C — no CTCP. CTCP frames start with \x01; ACTION
        // (/me …) is allowed through since channels-without-actions
        // are unusable on modern networks.
        if self.modes.extended_flags.contains(&'C') {
            let bytes = text.as_bytes();
            if bytes.first() == Some(&0x01) {
                // ACTION check: body starts with "\x01ACTION"
                let is_action = text.as_bytes().len() >= 8
                    && text.as_bytes()[..7].eq_ignore_ascii_case(b"\x01ACTION");
                if !is_action {
                    return Err("CTCPs are not permitted on this channel (+C)");
                }
            }
        }
        // +c — no colour/formatting escape codes. mIRC-style \x03
        // (colour), \x02 (bold), \x1f (underline), \x1d (italic),
        // \x16 (reverse), \x0f (reset) are all stripped. We reject
        // rather than strip so the sender knows.
        if self.modes.extended_flags.contains(&'c') {
            if text.bytes().any(|b| matches!(b, 0x02 | 0x03 | 0x04 | 0x0f | 0x16 | 0x1d | 0x1f)) {
                return Err("Colour/formatting codes are not permitted on this channel (+c)");
            }
        }
        Ok(())
    }

    /// Check if a user matches any ban mask.
    pub fn is_banned(&self, prefix: &str) -> bool {
        self.bans
            .iter()
            .any(|b| wildcard_match(&b.mask, prefix))
    }

    /// Check if a user can join this channel.
    pub fn can_join(
        &self,
        id: &ClientId,
        prefix: &str,
        key: Option<&str>,
        is_account: bool,
        is_tls: bool,
    ) -> JoinCheck {
        if self.is_member(id) {
            return JoinCheck::AlreadyMember;
        }
        // Invites bypass +b / +i / +k / +l / +r / +z per standard
        // IRC semantics — user was explicitly let in.
        if self.invites.contains(id) {
            return JoinCheck::Ok;
        }
        if self.is_banned(prefix) {
            return JoinCheck::Banned;
        }
        if self.modes.invite_only {
            return JoinCheck::InviteOnly;
        }
        // +r — authenticated users only.
        if self.modes.extended_flags.contains(&'r') && !is_account {
            return JoinCheck::RegisteredOnly;
        }
        // +z — SSL-only.
        if self.modes.extended_flags.contains(&'z') && !is_tls {
            return JoinCheck::SslOnly;
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
    /// `+r` set and the user has no authenticated account.
    RegisteredOnly,
    /// `+z` set and the user is not on a TLS connection.
    SslOnly,
}

/// Simple IRC wildcard matching (* and ?), rfc1459-case-insensitive.
pub(crate) fn wildcard_match(pattern: &str, input: &str) -> bool {
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
