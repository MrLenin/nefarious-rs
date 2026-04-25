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
    /// Original wire form of the ban mask. Always preserved so
    /// `MODE +b` listings, BURST, and `RPL_BANLIST` can re-emit
    /// exactly what the operator typed (modulo `pretty_mask`
    /// canonicalisation that nef applies to the host segment of
    /// non-extbans).
    pub mask: String,
    pub set_by: String,
    pub set_at: chrono::DateTime<chrono::Utc>,
    /// Parsed extban view, when `mask` starts with `~` and the
    /// payload was a recognised extban form. `None` for plain
    /// `nick!user@host` masks, or for `~x:` masks where extbans
    /// were disabled at parse time. The matcher uses `Some` to
    /// dispatch type-specific checks; on `None` it falls through
    /// to the standard hostmask path.
    pub extban: Option<ExtBan>,
}

/// One ext-ban activity flag — what a ban *blocks*. Mirrors
/// nefarious2's `EBAN_QUIET` / `EBAN_NICK` etc. (the activity
/// half of the C bitmask). A ban with no activity flag is "hard"
/// and blocks every action; an activity-flagged ban only blocks
/// the specified activity (so `~q:foo` quiets but allows JOIN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExtBanActivity {
    /// `~q` — silenced; can join but can't speak.
    Quiet,
    /// `~n` — can't change nick while in-channel.
    NoNick,
}

/// One ext-ban match-criterion. Each variant is a different way
/// of identifying which users a ban applies to. Composed with
/// activity flags via `ExtBan` — e.g. `~q:~a:foo` is
/// `mask = Account("foo"); activity = [Quiet]`.
#[derive(Debug, Clone)]
pub enum ExtBanMatch {
    /// `~a:<glob>` — match user's logged-in account name.
    Account(String),
    /// `~r:<glob>` — match user's realname (gecos).
    Realname(String),
    /// `~m:<glob>` — match user's DNSBL mark (any user).
    Mark(String),
    /// `~M:<glob>` — match DNSBL mark, but only for non-authed
    /// users. Lets operators auto-mute spambots while sparing
    /// SASL'd legitimate users on the same provider.
    MarkUnauthed(String),
    /// `~c:[@%+]<channel>` — match users currently in the named
    /// channel. Optional prefix narrows to ops/halfops/voiced.
    InChannel { prefix: Option<char>, channel: String },
    /// `~j:<channel>` — recursive: match anyone banned on the
    /// named channel. Bounded by `EXTBAN_j_MAXDEPTH` /
    /// `EXTBAN_j_MAXPERCHAN`.
    JoinedBan(String),
    /// Standard nick!user@host hostmask retained at the leaf of
    /// an activity-only extban (e.g. `~q:nick!user@host`).
    Hostmask(String),
}

/// Parsed extended ban. Carries the original wire form, the
/// activity flags it imposes, the match criterion, and a
/// negation flag (`~!type:mask` matches users who do NOT match
/// the criterion). Composed by the parser; consumed by the
/// matcher (added in a later commit).
#[derive(Debug, Clone)]
pub struct ExtBan {
    /// The set of activities this ban blocks. Empty means
    /// "blocks everything" (a hard ban — JOIN, MSG, NICK).
    pub activities: Vec<ExtBanActivity>,
    /// What the ban matches.
    pub criterion: ExtBanMatch,
    /// `~!` negates the criterion match. So
    /// `~!a:goodaccount` matches anyone whose account is NOT
    /// "goodaccount".
    pub negate: bool,
}

impl ExtBan {
    /// Parse `mask` (the full wire form, leading `~` and all)
    /// into an `ExtBan`. Returns `None` when the input doesn't
    /// start with `~`, when the type character is unrecognised,
    /// or when the type is disabled in the supplied config.
    /// Activity-only prefixes can stack (e.g. `~q:~n:mask`); the
    /// parser walks them in a single pass.
    ///
    /// Mirrors nefarious2 channel.c::parse_extban with a 5-level
    /// recursion cap on activity stacking.
    pub fn parse(mask: &str, cfg: &irc_config::Config) -> Option<Self> {
        if !cfg.extbans_enabled() {
            return None;
        }
        let mut rest = mask.strip_prefix('~')?;
        let mut activities: Vec<ExtBanActivity> = Vec::new();
        let mut negate = false;
        let mut depth = 0;

        loop {
            if depth >= 5 {
                return None;
            }
            depth += 1;

            // Optional `!` negate immediately after `~`. Only
            // legal once at the head; nested `~!~!` is junk.
            let (neg_here, after_neg) = match rest.strip_prefix('!') {
                Some(r) => (true, r),
                None => (false, rest),
            };

            let type_char = after_neg.chars().next()?;
            if !cfg.extban_type_enabled(type_char) {
                return None;
            }

            // Activity types stack via nested `~q:~n:mask`. The
            // delimiter after them is `:`. Match types (a, c,
            // j, r, m, M) terminate the parse with `:value`.
            match type_char {
                'q' | 'n' => {
                    activities.push(if type_char == 'q' {
                        ExtBanActivity::Quiet
                    } else {
                        ExtBanActivity::NoNick
                    });
                    if neg_here {
                        negate = true;
                    }
                    let body = after_neg.get(1..)?;
                    let after_colon = body.strip_prefix(':')?;
                    if let Some(nested) = after_colon.strip_prefix('~') {
                        rest = nested;
                        continue;
                    }
                    // No further `~`; activity-only ban with a
                    // plain hostmask leaf.
                    return Some(ExtBan {
                        activities,
                        criterion: ExtBanMatch::Hostmask(after_colon.to_string()),
                        negate,
                    });
                }
                'a' | 'r' | 'm' | 'M' | 'c' | 'j' => {
                    if neg_here {
                        negate = true;
                    }
                    let body = after_neg.get(1..)?;
                    let value = body.strip_prefix(':')?.to_string();
                    if value.is_empty() {
                        return None;
                    }
                    let criterion = match type_char {
                        'a' => ExtBanMatch::Account(value),
                        'r' => ExtBanMatch::Realname(value),
                        'm' => ExtBanMatch::Mark(value),
                        'M' => ExtBanMatch::MarkUnauthed(value),
                        'c' => parse_in_channel(&value)?,
                        'j' => ExtBanMatch::JoinedBan(value),
                        _ => unreachable!(),
                    };
                    return Some(ExtBan {
                        activities,
                        criterion,
                        negate,
                    });
                }
                _ => return None,
            }
        }
    }
}

fn parse_in_channel(value: &str) -> Option<ExtBanMatch> {
    let (prefix, channel) = match value.chars().next()? {
        c @ ('@' | '%' | '+') => (Some(c), value.get(1..)?.to_string()),
        _ => (None, value.to_string()),
    };
    if channel.is_empty() {
        None
    } else {
        Some(ExtBanMatch::InChannel { prefix, channel })
    }
}

#[cfg(test)]
mod extban_tests {
    use super::*;

    fn cfg_all_on() -> irc_config::Config {
        irc_config::Config::from_str_with_includes(
            "General { name = \"x\"; numeric = 1; };
             Features {
                EXTBANS = TRUE;
                EXTBAN_a = TRUE; EXTBAN_c = TRUE; EXTBAN_j = TRUE;
                EXTBAN_m = TRUE; EXTBAN_M = TRUE; EXTBAN_n = TRUE;
                EXTBAN_q = TRUE; EXTBAN_r = TRUE;
             };",
            std::path::Path::new("."),
        )
        .expect("config")
    }

    #[test]
    fn account_extban() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~a:bob", &cfg).expect("parse");
        assert!(matches!(eb.criterion, ExtBanMatch::Account(ref s) if s == "bob"));
        assert!(eb.activities.is_empty());
        assert!(!eb.negate);
    }

    #[test]
    fn negated_account_extban() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~!a:bob", &cfg).expect("parse");
        assert!(eb.negate);
        assert!(matches!(eb.criterion, ExtBanMatch::Account(_)));
    }

    #[test]
    fn quiet_with_account() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~q:~a:bob", &cfg).expect("parse");
        assert_eq!(eb.activities, vec![ExtBanActivity::Quiet]);
        assert!(matches!(eb.criterion, ExtBanMatch::Account(_)));
    }

    #[test]
    fn quiet_with_hostmask() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~q:nick!user@host", &cfg).expect("parse");
        assert_eq!(eb.activities, vec![ExtBanActivity::Quiet]);
        assert!(matches!(eb.criterion, ExtBanMatch::Hostmask(ref s) if s == "nick!user@host"));
    }

    #[test]
    fn channel_extban_with_prefix() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~c:@#evil", &cfg).expect("parse");
        match eb.criterion {
            ExtBanMatch::InChannel { prefix, channel } => {
                assert_eq!(prefix, Some('@'));
                assert_eq!(channel, "#evil");
            }
            _ => panic!("expected InChannel"),
        }
    }

    #[test]
    fn rejects_unknown_type() {
        let cfg = cfg_all_on();
        assert!(ExtBan::parse("~z:foo", &cfg).is_none());
    }

    #[test]
    fn rejects_when_extbans_disabled() {
        let cfg = irc_config::Config::from_str_with_includes(
            "General { name = \"x\"; numeric = 1; };
             Features { EXTBANS = FALSE; };",
            std::path::Path::new("."),
        )
        .expect("config");
        assert!(ExtBan::parse("~a:bob", &cfg).is_none());
    }

    #[test]
    fn rejects_disabled_type() {
        let cfg = irc_config::Config::from_str_with_includes(
            "General { name = \"x\"; numeric = 1; };
             Features { EXTBANS = TRUE; EXTBAN_a = FALSE; EXTBAN_q = TRUE; };",
            std::path::Path::new("."),
        )
        .expect("config");
        assert!(ExtBan::parse("~a:bob", &cfg).is_none());
    }
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
