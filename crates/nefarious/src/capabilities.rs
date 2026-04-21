//! IRCv3 capability set.
//!
//! Mirrors the C branch's `enum Capab` in
//! `nefarious2/include/capab.h` so cap names, ordering and the CAP
//! negotiation wire format stay identical. Per the project design
//! rule, a mixed Rust/C network must produce the same CAP LS output
//! and the same REQ/ACK/NAK decisions.
//!
//! Phase 2 lands the negotiation framework (2.1) and then flips each
//! capability's `advertised` bit as the behaviour behind it is
//! implemented. Clients can only enable caps that are currently
//! advertised; requesting an unadvertised cap results in a NAK.

use std::collections::HashSet;

/// Every IRCv3 capability nefarious understands. Variants without a
/// behaviour yet are still listed here so subsequent phases don't have
/// to edit the enum — only the `advertised_caps` set in
/// `ServerState::new` grows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    CapNotify,
    MessageTags,
    ServerTime,
    AccountTag,
    EchoMessage,
    Batch,
    LabeledResponse,
    MultiPrefix,
    UserhostInNames,
    InviteNotify,
    AwayNotify,
    StandardReplies,
    Chghost,
    Setname,
    AccountNotify,
    ExtendedJoin,
    Sasl,
}

impl Capability {
    /// Wire name as it appears in `CAP LS` and `CAP REQ`. Must match
    /// `nefarious2/include/capab.h` exactly.
    pub fn name(self) -> &'static str {
        match self {
            Self::CapNotify => "cap-notify",
            Self::MessageTags => "message-tags",
            Self::ServerTime => "server-time",
            Self::AccountTag => "account-tag",
            Self::EchoMessage => "echo-message",
            Self::Batch => "batch",
            Self::LabeledResponse => "labeled-response",
            Self::MultiPrefix => "multi-prefix",
            Self::UserhostInNames => "userhost-in-names",
            Self::InviteNotify => "invite-notify",
            Self::AwayNotify => "away-notify",
            Self::StandardReplies => "standard-replies",
            Self::Chghost => "chghost",
            Self::Setname => "setname",
            Self::AccountNotify => "account-notify",
            Self::ExtendedJoin => "extended-join",
            Self::Sasl => "sasl",
        }
    }

    /// Parse a capability name from the wire. Returns `None` for
    /// unknown / unsupported capabilities (those will be NAK'd).
    pub fn from_name(s: &str) -> Option<Self> {
        match s {
            "cap-notify" => Some(Self::CapNotify),
            "message-tags" => Some(Self::MessageTags),
            "server-time" => Some(Self::ServerTime),
            "account-tag" => Some(Self::AccountTag),
            "echo-message" => Some(Self::EchoMessage),
            "batch" => Some(Self::Batch),
            "labeled-response" => Some(Self::LabeledResponse),
            "multi-prefix" => Some(Self::MultiPrefix),
            "userhost-in-names" => Some(Self::UserhostInNames),
            "invite-notify" => Some(Self::InviteNotify),
            "away-notify" => Some(Self::AwayNotify),
            "standard-replies" => Some(Self::StandardReplies),
            "chghost" => Some(Self::Chghost),
            "setname" => Some(Self::Setname),
            "account-notify" => Some(Self::AccountNotify),
            "extended-join" => Some(Self::ExtendedJoin),
            "sasl" => Some(Self::Sasl),
            _ => None,
        }
    }

    /// Metadata attached to this cap in `CAP LS 302` output
    /// (`capname=value`). None means a bare capname. Used for `sasl` to
    /// list supported mechanisms.
    pub fn ls_value(self) -> Option<&'static str> {
        match self {
            // Phase 3.3 ships PLAIN + EXTERNAL; 3.4–3.5 will extend
            // this list as SCRAM-SHA-256 and OAUTHBEARER land.
            Self::Sasl => Some("PLAIN,EXTERNAL"),
            _ => None,
        }
    }
}

/// Server-level set of capabilities currently advertised to clients.
/// A cap must be in this set before a client can successfully REQ it.
/// Each Phase 2 sub-phase flips the relevant cap on as its behaviour
/// lands; Phase 2.1 (this commit) only advertises `cap-notify`, which
/// is pure plumbing.
pub fn default_advertised_caps() -> HashSet<Capability> {
    let mut set = HashSet::new();
    set.insert(Capability::CapNotify);
    // Phase 2.2 — tagged outbound events.
    //
    // `message-tags` is the umbrella capability that governs whether
    // a client accepts server-generated tags on inbound messages. The
    // IRCv3 `msgid` spec requires it as a prerequisite: we MUST NOT
    // emit `@msgid=…` to clients that haven't negotiated message-tags.
    set.insert(Capability::MessageTags);
    set.insert(Capability::ServerTime);
    set.insert(Capability::AccountTag);
    // Phase 2.3 — self-echo of PRIVMSG/NOTICE.
    set.insert(Capability::EchoMessage);
    // Phase 2.4 — batch framing + labeled-response.
    set.insert(Capability::Batch);
    set.insert(Capability::LabeledResponse);
    // Phase 2.5 — richer NAMES/WHO formatting.
    set.insert(Capability::MultiPrefix);
    set.insert(Capability::UserhostInNames);
    // Phase 2.6 — notify-style broadcasts for state changes.
    set.insert(Capability::AwayNotify);
    set.insert(Capability::InviteNotify);
    set.insert(Capability::Chghost);
    set.insert(Capability::Setname);
    set.insert(Capability::StandardReplies);
    // Phase 2.7 — JOIN payload + login/logout broadcast.
    set.insert(Capability::ExtendedJoin);
    set.insert(Capability::AccountNotify);
    // Phase 2.8 — SASL negotiation surface (mechanisms stubbed until
    // Phase 3). ls_value() on the cap advertises the mechanism list.
    set.insert(Capability::Sasl);
    set
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL_CAPS: &[Capability] = &[
        Capability::CapNotify,
        Capability::MessageTags,
        Capability::ServerTime,
        Capability::AccountTag,
        Capability::EchoMessage,
        Capability::Batch,
        Capability::LabeledResponse,
        Capability::MultiPrefix,
        Capability::UserhostInNames,
        Capability::InviteNotify,
        Capability::AwayNotify,
        Capability::StandardReplies,
        Capability::Chghost,
        Capability::Setname,
        Capability::AccountNotify,
        Capability::ExtendedJoin,
        Capability::Sasl,
    ];

    #[test]
    fn roundtrip_all_known_names() {
        for cap in ALL_CAPS {
            assert_eq!(Capability::from_name(cap.name()), Some(*cap));
        }
    }

    #[test]
    fn unknown_name_returns_none() {
        assert_eq!(Capability::from_name("draft/chathistory"), None);
        assert_eq!(Capability::from_name(""), None);
        assert_eq!(Capability::from_name("foo"), None);
    }

    #[test]
    fn default_advertised_includes_cap_notify() {
        let caps = default_advertised_caps();
        assert!(caps.contains(&Capability::CapNotify));
    }

    /// Parity check: every advertised cap must have a name recognised
    /// by C nefarious2 (from `include/capab.h`). The whitelist is
    /// copied verbatim from the C header. A mismatch here means we've
    /// invented a cap name that won't federate.
    #[test]
    fn every_advertised_cap_name_matches_c_reference() {
        const C_KNOWN: &[&str] = &[
            "multi-prefix",
            "userhost-in-names",
            "extended-join",
            "away-notify",
            "account-notify",
            "sasl",
            "cap-notify",
            "server-time",
            "echo-message",
            "account-tag",
            "chghost",
            "invite-notify",
            "labeled-response",
            "batch",
            "setname",
            "standard-replies",
            "message-tags",
        ];
        for cap in default_advertised_caps() {
            let n = cap.name();
            assert!(
                C_KNOWN.contains(&n),
                "advertised cap {n} is not in the C parity whitelist"
            );
        }
    }
}
