/// P10 protocol tokens — short 1-2 character commands for S2S communication.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum P10Token {
    // Connection/registration
    Pass,
    Server,
    Squit,
    Ping,
    Pong,
    Error,

    // User lifecycle
    Nick,
    Quit,
    Kill,
    Account,
    Away,

    // Channel lifecycle
    Burst,
    Create,
    Destruct,
    Join,
    Part,
    Kick,
    Mode,
    Topic,
    Invite,

    // Messaging
    Privmsg,
    Notice,
    Wallops,

    // Burst control
    EndOfBurst,
    EndOfBurstAck,

    // Services
    SvsNick,
    SvsJoin,
    SvsPart,
    Fake,
    Mark,

    // Bans
    Gline,
    Shun,
    Jupe,
    Zline,

    // Metadata
    Metadata,

    // Bouncer (nefarious2-specific)
    BouncerSession,  // BS — session lifecycle (account, sessid, channels)
    BouncerTransfer, // BX — alias create/destroy/promote (numeric swap)

    // IRCv3 setname cap (nefarious2 uses token SR for realname changes)
    Setname,

    // Oper privileges. Token is the full word "PRIVS" — nefarious2 did
    // not mint a short form (see include/msg.h:TOK_PRIVS).
    Privs,

    // Information queries forwarded across servers.
    Whois,

    // Oper-bypass channel mode ops. OPMODE behaves like MODE but the
    // receiver skips ops/TS checks; CLEARMODE wipes all set modes
    // and per-member op/voice flags on a channel at once.
    Opmode,
    Clearmode,

    // Per-user sender filter. Wire form:
    //   <sender> U <target_or_*> <silence_updates>
    // where <sender> is the silenced user's numeric (or the server's
    // when propagated), <target> is the directed forward target
    // numeric (or "*" for a broadcast), and <silence_updates> is a
    // comma-separated list of [+-]?~?<mask> tokens.
    Silence,

    // Unknown token
    Unknown(String),
}

impl P10Token {
    /// Parse a token string (1-2 chars) into a P10Token.
    pub fn from_token(s: &str) -> Self {
        match s {
            "PA" => P10Token::Pass,
            "S" => P10Token::Server,
            "SQ" => P10Token::Squit,
            "G" => P10Token::Ping,
            "Z" => P10Token::Pong,
            "Y" => P10Token::Error,

            "N" => P10Token::Nick,
            "Q" => P10Token::Quit,
            "D" => P10Token::Kill,
            "AC" => P10Token::Account,
            "A" => P10Token::Away,

            "B" => P10Token::Burst,
            "C" => P10Token::Create,
            "DE" => P10Token::Destruct,
            "J" => P10Token::Join,
            "L" => P10Token::Part,
            "K" => P10Token::Kick,
            "M" => P10Token::Mode,
            "T" => P10Token::Topic,
            "I" => P10Token::Invite,

            "P" => P10Token::Privmsg,
            "O" => P10Token::Notice,
            "WA" => P10Token::Wallops,

            "EB" => P10Token::EndOfBurst,
            "EA" => P10Token::EndOfBurstAck,

            "SN" => P10Token::SvsNick,
            "SJ" => P10Token::SvsJoin,
            "SP" => P10Token::SvsPart,
            "FA" => P10Token::Fake,
            "MK" => P10Token::Mark,

            "GL" => P10Token::Gline,
            "SU" => P10Token::Shun,
            "JU" => P10Token::Jupe,
            "ZL" => P10Token::Zline,

            "MD" => P10Token::Metadata,

            "BS" => P10Token::BouncerSession,
            "BX" => P10Token::BouncerTransfer,

            "SR" => P10Token::Setname,

            "PRIVS" => P10Token::Privs,

            "W" => P10Token::Whois,
            "WHOIS" => P10Token::Whois,

            "OM" => P10Token::Opmode,
            "OPMODE" => P10Token::Opmode,
            "CM" => P10Token::Clearmode,
            "CLEARMODE" => P10Token::Clearmode,

            "U" => P10Token::Silence,
            "SILENCE" => P10Token::Silence,

            // Also accept full command names
            "PASS" => P10Token::Pass,
            "SERVER" => P10Token::Server,
            "SQUIT" => P10Token::Squit,
            "PING" => P10Token::Ping,
            "PONG" => P10Token::Pong,
            "ERROR" => P10Token::Error,
            "NICK" => P10Token::Nick,
            "QUIT" => P10Token::Quit,
            "KILL" => P10Token::Kill,
            "ACCOUNT" => P10Token::Account,
            "AWAY" => P10Token::Away,
            "BURST" => P10Token::Burst,
            "CREATE" => P10Token::Create,
            "DESTRUCT" => P10Token::Destruct,
            "JOIN" => P10Token::Join,
            "PART" => P10Token::Part,
            "KICK" => P10Token::Kick,
            "MODE" => P10Token::Mode,
            "TOPIC" => P10Token::Topic,
            "INVITE" => P10Token::Invite,
            "PRIVMSG" => P10Token::Privmsg,
            "NOTICE" => P10Token::Notice,
            "WALLOPS" => P10Token::Wallops,
            "END_OF_BURST" => P10Token::EndOfBurst,
            "EOB_ACK" => P10Token::EndOfBurstAck,
            "GLINE" => P10Token::Gline,
            "METADATA" => P10Token::Metadata,
            "BOUNCER_SESSION" => P10Token::BouncerSession,
            "BOUNCER_TRANSFER" => P10Token::BouncerTransfer,
            "SETNAME" => P10Token::Setname,

            other => P10Token::Unknown(other.to_string()),
        }
    }

    /// Convert to token string for S2S output.
    pub fn to_token(&self) -> &str {
        match self {
            P10Token::Pass => "PA",
            P10Token::Server => "S",
            P10Token::Squit => "SQ",
            P10Token::Ping => "G",
            P10Token::Pong => "Z",
            P10Token::Error => "Y",
            P10Token::Nick => "N",
            P10Token::Quit => "Q",
            P10Token::Kill => "D",
            P10Token::Account => "AC",
            P10Token::Away => "A",
            P10Token::Burst => "B",
            P10Token::Create => "C",
            P10Token::Destruct => "DE",
            P10Token::Join => "J",
            P10Token::Part => "L",
            P10Token::Kick => "K",
            P10Token::Mode => "M",
            P10Token::Topic => "T",
            P10Token::Invite => "I",
            P10Token::Privmsg => "P",
            P10Token::Notice => "O",
            P10Token::Wallops => "WA",
            P10Token::EndOfBurst => "EB",
            P10Token::EndOfBurstAck => "EA",
            P10Token::SvsNick => "SN",
            P10Token::SvsJoin => "SJ",
            P10Token::SvsPart => "SP",
            P10Token::Fake => "FA",
            P10Token::Mark => "MK",
            P10Token::Gline => "GL",
            P10Token::Shun => "SU",
            P10Token::Jupe => "JU",
            P10Token::Zline => "ZL",
            P10Token::Metadata => "MD",
            P10Token::BouncerSession => "BS",
            P10Token::BouncerTransfer => "BX",
            P10Token::Setname => "SR",
            P10Token::Privs => "PRIVS",
            P10Token::Whois => "W",
            P10Token::Opmode => "OM",
            P10Token::Clearmode => "CM",
            P10Token::Silence => "U",
            P10Token::Unknown(s) => s,
        }
    }
}

impl std::fmt::Display for P10Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_token())
    }
}
