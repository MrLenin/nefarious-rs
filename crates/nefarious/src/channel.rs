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
    /// Per-member CHFL_DELAYED. Set when the user joins a `+D`
    /// channel: their JOIN isn't fanned out to other members,
    /// they're filtered from NAMES, and the channel acts as if
    /// they aren't there until they "reveal" themselves by
    /// speaking, getting opped, parting, etc. Mirrors
    /// nefarious2 channel.h:84 `CHFL_DELAYED 0x40000`.
    pub delayed: bool,
}

impl MembershipFlags {
    /// Highest rank held in the channel. Used by extban `~c`
    /// matching to compare against an `[@%+]` prefix
    /// requirement.
    pub fn to_status(&self) -> InChannelStatus {
        if self.op {
            InChannelStatus::Op
        } else if self.halfop {
            InChannelStatus::HalfOp
        } else if self.voice {
            InChannelStatus::Voice
        } else {
            InChannelStatus::Plain
        }
    }

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

/// Status the user holds in a channel from their perspective.
/// Used by `~c:[@%+]channel` to narrow the match by membership
/// rank — `~c:@#evil` matches only ops in `#evil`, `~c:%#evil`
/// halfops or above, `~c:+#evil` voiced or above, `~c:#evil`
/// any member regardless of rank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InChannelStatus {
    Plain,
    Voice,
    HalfOp,
    Op,
}

/// Snapshot of the user attributes an extban matcher needs.
///
/// Built once per ban-check sweep so we don't re-read the
/// `Client` / `RemoteClient` structs (which would mean a lock
/// per ban). Borrowed view; the caller owns the strings.
///
/// `channels` is the user's joined-channels list with the
/// status they hold in each, used by `~c`. Empty slice is
/// fine — `~c` simply never matches. `~j` remains pending and
/// always returns false here regardless of input.
#[derive(Debug, Clone, Copy)]
pub struct ExtBanUserView<'a> {
    /// `nick!user@host` — the canonical RFC form. Hostmask
    /// leaves of activity-only extbans (e.g. `~q:nick!user@host`)
    /// match against this.
    pub prefix: &'a str,
    /// Logged-in account name, if any. `~a` matches against it;
    /// `~M` (mark-but-only-unauthed) requires this to be `None`.
    pub account: Option<&'a str>,
    /// Realname / GECOS field. `~r` matches against it.
    pub realname: &'a str,
    /// DNSBL mark stored at connect time when a mark-action
    /// zone fired. `~m` matches against it; `~M` matches it
    /// only when `account` is None. Free-form text (we store as
    /// `<zone>: <reason>`).
    pub dnsbl_mark: Option<&'a str>,
    /// Channels the user is currently in, with their status in
    /// each. Used by `~c`. Channel name comparison is done with
    /// `wildcard_match` so `~c:#test*` works.
    pub channels: &'a [(&'a str, InChannelStatus)],
}

impl ExtBan {
    /// Does this extban apply to the user described by `view`?
    ///
    /// Returns the *match-criterion* result, including any `~!`
    /// negation. The activity flag (whether this ban *blocks*
    /// JOIN vs MSG vs NICK) is a separate concern handled by
    /// `applies_to` — this method only answers "does the user
    /// match this mask".
    ///
    /// `~j` always returns false here; its recursive-banlist
    /// walk lives above this layer and needs extra arguments.
    /// It lands in the next commit.
    pub fn matches(&self, view: &ExtBanUserView<'_>) -> bool {
        let raw = match &self.criterion {
            ExtBanMatch::Account(glob) => view
                .account
                .is_some_and(|a| wildcard_match(glob, a)),
            ExtBanMatch::Realname(glob) => wildcard_match(glob, view.realname),
            ExtBanMatch::Mark(glob) => view
                .dnsbl_mark
                .is_some_and(|m| wildcard_match(glob, m)),
            ExtBanMatch::MarkUnauthed(glob) => {
                view.account.is_none()
                    && view.dnsbl_mark.is_some_and(|m| wildcard_match(glob, m))
            }
            ExtBanMatch::Hostmask(mask) => wildcard_match(mask, view.prefix),
            ExtBanMatch::InChannel { prefix, channel } => {
                view.channels.iter().any(|(name, status)| {
                    wildcard_match(channel, name) && status_meets(*status, *prefix)
                })
            }
            ExtBanMatch::JoinedBan(_) => {
                // ~j needs the channel registry + recursion
                // bookkeeping; a free-standing matcher can't
                // resolve it. Lands in the next commit as a
                // method that takes a registry handle.
                false
            }
        };
        if self.negate { !raw } else { raw }
    }

    /// Does this ban apply to the given activity?
    ///
    /// Mirrors nefarious2 channel.c::find_ban's activity gate:
    ///   `(banlist->extban.flags & extbantype)
    ///    || !(banlist->extban.flags & EBAN_ACTIVITY)`
    ///
    /// In words:
    /// - A ban with no activity flag (a "hard ban" like
    ///   `~a:foo`) applies to every activity — JOIN, MSG, NICK.
    /// - A ban with activity flags (`~q:...`, `~n:...`) only
    ///   applies when the caller asks about that specific
    ///   activity. So `~q:nick!user@host` *does* gate MSG
    ///   delivery (`activity = Some(Quiet)`) but does *not*
    ///   gate JOIN (`activity = None`).
    ///
    /// `activity = None` means "default ban-check" — the
    /// JOIN-time path. Pass `Some(Quiet)` for the speak gate,
    /// `Some(NoNick)` for the NICK gate.
    pub fn applies_to(&self, activity: Option<ExtBanActivity>) -> bool {
        match activity {
            Some(act) => self.activities.contains(&act) || self.activities.is_empty(),
            None => self.activities.is_empty(),
        }
    }
}

/// Walk a channel's banlist and return the first entry whose
/// criterion matches `view` for the given `activity`. Mirrors
/// nefarious2 channel.c::find_ban's outer loop.
///
/// `~j:<channel>` resolves recursively against the named
/// channel's banlist. `fetch_banlist` is the channel registry
/// handle — given a channel name it returns that channel's
/// `&[BanEntry]` if known. We pass it in (rather than taking
/// a `&ServerState`) so the matcher is testable without spinning
/// up the whole server.
///
/// Recursion is bounded:
/// - **depth**: the caller's starting depth, capped at
///   `EXTBAN_j_MAXDEPTH`. Each `~j` recursion increments by one.
/// - **per-channel `~j` cap** (`EXTBAN_j_MAXPERCHAN`): we count
///   `~j` entries seen *in this banlist* and stop processing
///   them past the cap. Entries above the cap are skipped, not
///   treated as matches; the rest of the banlist is still
///   walked.
///
/// Plain (non-extended) bans match via the existing
/// `wildcard_match` against `view.prefix`.
pub fn find_extban_match<'a, F>(
    bans: &'a [BanEntry],
    view: &ExtBanUserView<'_>,
    activity: Option<ExtBanActivity>,
    depth: u32,
    max_depth: u32,
    max_per_chan: u32,
    fetch_banlist: &F,
) -> Option<&'a BanEntry>
where
    F: Fn(&str) -> Option<Vec<BanEntry>>,
{
    let mut j_seen = 0u32;
    for ban in bans {
        match &ban.extban {
            Some(eb) => {
                if !eb.applies_to(activity) {
                    continue;
                }
                let raw_match = match &eb.criterion {
                    ExtBanMatch::JoinedBan(target) => {
                        j_seen += 1;
                        if j_seen > max_per_chan {
                            // Per-chan cap reached — skip the
                            // rest of this entry, keep walking
                            // the banlist.
                            continue;
                        }
                        if depth >= max_depth {
                            // Depth cap reached — don't recurse.
                            continue;
                        }
                        match fetch_banlist(target) {
                            Some(other_bans) => find_extban_match(
                                &other_bans,
                                view,
                                activity,
                                depth + 1,
                                max_depth,
                                max_per_chan,
                                fetch_banlist,
                            )
                            .is_some(),
                            None => false,
                        }
                    }
                    _ => eb.matches(view),
                };
                let matched = if eb.negate
                    && matches!(&eb.criterion, ExtBanMatch::JoinedBan(_))
                {
                    // ~!j is unusual but supported: negate the
                    // recursive result. (matches() already
                    // handles negate for non-~j criteria.)
                    !raw_match
                } else {
                    raw_match
                };
                if matched {
                    return Some(ban);
                }
            }
            None => {
                // Plain (non-extended) ban — only counts when
                // the caller is doing the default ban check.
                // A `~q:foo` MSG-gate sweep wouldn't apply a
                // plain JOIN ban; that's the caller's split.
                if activity.is_none() && wildcard_match(&ban.mask, view.prefix) {
                    return Some(ban);
                }
            }
        }
    }
    None
}

/// True when the user's status in a channel meets the
/// `~c:[@%+]channel` rank requirement. `Op > HalfOp > Voice >
/// Plain` — a higher rank also satisfies a lower-rank match,
/// matching nefarious2's `IsChanOp || IsHalfOp || HasVoice`
/// fall-through chain in find_ban (channel.c:553-559).
fn status_meets(status: InChannelStatus, required_prefix: Option<char>) -> bool {
    let required_rank = match required_prefix {
        None => 0,
        Some('+') => 1,
        Some('%') => 2,
        Some('@') => 3,
        Some(_) => return false,
    };
    let user_rank = match status {
        InChannelStatus::Plain => 0,
        InChannelStatus::Voice => 1,
        InChannelStatus::HalfOp => 2,
        InChannelStatus::Op => 3,
    };
    user_rank >= required_rank
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

    fn view<'a>(
        prefix: &'a str,
        account: Option<&'a str>,
        realname: &'a str,
        mark: Option<&'a str>,
    ) -> ExtBanUserView<'a> {
        ExtBanUserView {
            prefix,
            account,
            realname,
            dnsbl_mark: mark,
            channels: &[],
        }
    }

    fn view_in<'a>(
        prefix: &'a str,
        channels: &'a [(&'a str, InChannelStatus)],
    ) -> ExtBanUserView<'a> {
        ExtBanUserView {
            prefix,
            account: None,
            realname: "",
            dnsbl_mark: None,
            channels,
        }
    }

    #[test]
    fn match_account_glob() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~a:bo*", &cfg).unwrap();
        assert!(eb.matches(&view("a!b@c", Some("bob"), "Bob", None)));
        assert!(eb.matches(&view("a!b@c", Some("boris"), "Bob", None)));
        assert!(!eb.matches(&view("a!b@c", Some("alice"), "Bob", None)));
        // Unauthenticated never matches ~a.
        assert!(!eb.matches(&view("a!b@c", None, "Bob", None)));
    }

    #[test]
    fn match_account_negated() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~!a:trusted", &cfg).unwrap();
        // Anyone NOT logged in as `trusted` matches.
        assert!(eb.matches(&view("a!b@c", Some("alice"), "x", None)));
        assert!(eb.matches(&view("a!b@c", None, "x", None)));
        assert!(!eb.matches(&view("a!b@c", Some("trusted"), "x", None)));
    }

    #[test]
    fn match_realname() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~r:*spam*", &cfg).unwrap();
        assert!(eb.matches(&view("a!b@c", None, "buy spam now", None)));
        assert!(!eb.matches(&view("a!b@c", None, "regular user", None)));
    }

    #[test]
    fn match_mark_any_user() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~m:*sorbs*", &cfg).unwrap();
        assert!(eb.matches(&view("a!b@c", Some("alice"), "x", Some("sorbs: listed"))));
        assert!(eb.matches(&view("a!b@c", None, "x", Some("sorbs: listed"))));
        assert!(!eb.matches(&view("a!b@c", None, "x", Some("dronebl: listed"))));
        assert!(!eb.matches(&view("a!b@c", None, "x", None)));
    }

    #[test]
    fn match_mark_unauthed_only() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~M:*sorbs*", &cfg).unwrap();
        // Mark hits but the user is authed — ~M spares them.
        assert!(!eb.matches(&view("a!b@c", Some("alice"), "x", Some("sorbs: listed"))));
        // Unauthed with mark — caught.
        assert!(eb.matches(&view("a!b@c", None, "x", Some("sorbs: listed"))));
    }

    #[test]
    fn match_hostmask_leaf() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~q:nick!user@*.evil.example", &cfg).unwrap();
        assert!(eb.matches(&view("nick!user@host.evil.example", None, "x", None)));
        assert!(!eb.matches(&view("nick!user@good.example", None, "x", None)));
    }

    #[test]
    fn match_in_channel_any_member() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~c:#evil", &cfg).unwrap();
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Plain)])));
        // Op also satisfies "any member".
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Op)])));
        // Different channel — no match.
        assert!(!eb.matches(&view_in("a!b@c", &[("#good", InChannelStatus::Plain)])));
        // Empty channels list — no match.
        assert!(!eb.matches(&view_in("a!b@c", &[])));
    }

    #[test]
    fn match_in_channel_op_prefix() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~c:@#evil", &cfg).unwrap();
        // Plain member doesn't satisfy `@` requirement.
        assert!(!eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Plain)])));
        assert!(!eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Voice)])));
        assert!(!eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::HalfOp)])));
        // Op satisfies it.
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Op)])));
    }

    #[test]
    fn match_in_channel_voice_prefix_falls_through() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~c:+#evil", &cfg).unwrap();
        // `+` requires voice or above. Plain doesn't qualify;
        // voice/halfop/op all do — matches m_mode/find_ban's
        // rank-fallthrough.
        assert!(!eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Plain)])));
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Voice)])));
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::HalfOp)])));
        assert!(eb.matches(&view_in("a!b@c", &[("#evil", InChannelStatus::Op)])));
    }

    #[test]
    fn match_in_channel_glob() {
        let cfg = cfg_all_on();
        let eb = ExtBan::parse("~c:#test*", &cfg).unwrap();
        assert!(eb.matches(&view_in("a!b@c", &[("#test1", InChannelStatus::Plain)])));
        assert!(eb.matches(&view_in("a!b@c", &[("#testing", InChannelStatus::Plain)])));
        assert!(!eb.matches(&view_in("a!b@c", &[("#other", InChannelStatus::Plain)])));
    }

    #[test]
    fn applies_to_hard_ban() {
        let cfg = cfg_all_on();
        // `~a:foo` has no activity flag — applies to every gate.
        let eb = ExtBan::parse("~a:foo", &cfg).unwrap();
        assert!(eb.applies_to(None)); // JOIN
        assert!(eb.applies_to(Some(ExtBanActivity::Quiet))); // MSG
        assert!(eb.applies_to(Some(ExtBanActivity::NoNick))); // NICK
    }

    #[test]
    fn applies_to_quiet_only() {
        let cfg = cfg_all_on();
        // `~q:foo` is a speak-only mute.
        let eb = ExtBan::parse("~q:nick!user@host", &cfg).unwrap();
        assert!(!eb.applies_to(None)); // doesn't gate JOIN
        assert!(eb.applies_to(Some(ExtBanActivity::Quiet))); // gates MSG
        assert!(!eb.applies_to(Some(ExtBanActivity::NoNick))); // doesn't gate NICK
    }

    #[test]
    fn applies_to_pending_jupe_criterion() {
        let cfg = cfg_all_on();
        // ExtBan::matches() returns false for ~j; the
        // resolver function find_extban_match handles it.
        let eb = ExtBan::parse("~j:#evil", &cfg).unwrap();
        assert!(!eb.matches(&view("a!b@c", Some("alice"), "x", None)));
    }

    fn ban(mask: &str, cfg: &irc_config::Config) -> BanEntry {
        BanEntry {
            mask: mask.to_string(),
            set_by: "test".to_string(),
            set_at: chrono::Utc::now(),
            extban: ExtBan::parse(mask, cfg),
        }
    }

    #[test]
    fn recursive_jupe_resolves() {
        let cfg = cfg_all_on();
        let other_bans = vec![ban("~a:bob", &cfg)];
        let bans = vec![ban("~j:#other", &cfg)];
        let v = view("a!b@c", Some("bob"), "x", None);
        let fetch = |name: &str| -> Option<Vec<BanEntry>> {
            if name == "#other" {
                Some(other_bans.clone())
            } else {
                None
            }
        };
        // Default depth: max_depth=1, max_per_chan=2.
        let hit = find_extban_match(&bans, &v, None, 0, 1, 2, &fetch);
        assert!(hit.is_some());
        // Different account — ~a:bob doesn't fire, so no match.
        let v2 = view("a!b@c", Some("alice"), "x", None);
        let miss = find_extban_match(&bans, &v2, None, 0, 1, 2, &fetch);
        assert!(miss.is_none());
    }

    #[test]
    fn recursive_jupe_respects_depth_cap() {
        let cfg = cfg_all_on();
        // chain: #a → #b → #c (which would hit) — at depth=1
        // we stop at #b and never see #c.
        let c_bans = vec![ban("~a:bob", &cfg)];
        let b_bans = vec![ban("~j:#c", &cfg)];
        let a_bans = vec![ban("~j:#b", &cfg)];
        let v = view("a!b@c", Some("bob"), "x", None);
        let c_clone = c_bans.clone();
        let b_clone = b_bans.clone();
        let fetch = move |name: &str| -> Option<Vec<BanEntry>> {
            match name {
                "#b" => Some(b_clone.clone()),
                "#c" => Some(c_clone.clone()),
                _ => None,
            }
        };
        // max_depth=1: walking #a → recurses into #b at depth 1;
        // depth 1 >= max_depth 1, so the ~j:#c entry inside #b
        // is skipped. Result: no match.
        assert!(find_extban_match(&a_bans, &v, None, 0, 1, 2, &fetch).is_none());
        // max_depth=2: #a → #b (depth 1) → #c (depth 2) hits.
        assert!(find_extban_match(&a_bans, &v, None, 0, 2, 2, &fetch).is_some());
    }

    #[test]
    fn recursive_jupe_respects_per_chan_cap() {
        let cfg = cfg_all_on();
        let target = vec![ban("~a:bob", &cfg)];
        // Banlist with three ~j entries — only the first two
        // get processed (per-chan cap default 2). Third is
        // skipped, so if the hit is in the third resolution it
        // never fires.
        let bans = vec![
            ban("~j:#empty1", &cfg),
            ban("~j:#empty2", &cfg),
            ban("~j:#real", &cfg),
        ];
        let v = view("a!b@c", Some("bob"), "x", None);
        let target_clone = target.clone();
        let fetch = move |name: &str| -> Option<Vec<BanEntry>> {
            match name {
                "#real" => Some(target_clone.clone()),
                _ => Some(Vec::new()),
            }
        };
        assert!(find_extban_match(&bans, &v, None, 0, 1, 2, &fetch).is_none());
        // Lift cap to 3 and the third entry resolves.
        assert!(find_extban_match(&bans, &v, None, 0, 1, 3, &fetch).is_some());
    }

    #[test]
    fn plain_ban_only_for_default_activity() {
        let cfg = cfg_all_on();
        let bans = vec![ban("alice!*@*", &cfg)];
        let v = view("alice!user@host", None, "x", None);
        let fetch = |_: &str| -> Option<Vec<BanEntry>> { None };
        // Default ban-check (None activity) → plain ban hits.
        assert!(find_extban_match(&bans, &v, None, 0, 1, 2, &fetch).is_some());
        // MSG-gate sweep (Some(Quiet)) → plain bans don't gate
        // MSG, so no match.
        assert!(
            find_extban_match(&bans, &v, Some(ExtBanActivity::Quiet), 0, 1, 2, &fetch)
                .is_none()
        );
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

    /// Check if a client holds the halfop (`+h`) flag in this
    /// channel. Used by MODE authority gating: per nefarious2
    /// m_mode.c:174-176, halfops can set `+v` / `-v` (voice
    /// only) but no other channel modes.
    pub fn is_halfop(&self, id: &ClientId) -> bool {
        self.members.get(id).is_some_and(|f| f.halfop)
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

    /// Check if a user can join this channel. Caller is
    /// responsible for the +b ban gate via
    /// `ServerState::is_user_banned_in` *before* invoking
    /// `can_join` — that path does the extban-aware async walk
    /// and constructs `JoinCheck::Banned` itself. This method
    /// only returns it as a placeholder for the legacy mask
    /// path that no longer exists; future refactors can remove
    /// the variant.
    pub fn can_join(
        &self,
        id: &ClientId,
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
