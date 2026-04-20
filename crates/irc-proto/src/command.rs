use std::fmt;

/// IRC commands supported by the server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Command {
    // Connection registration
    Cap,
    Nick,
    User,
    Pass,
    Ping,
    Pong,
    Quit,
    Error,

    // IRCv3 batch framing
    Batch,

    // Channel operations
    Join,
    Part,
    Topic,
    Kick,
    Invite,
    Names,
    List,

    // Messaging
    Privmsg,
    Notice,

    // Modes
    Mode,

    // Queries
    Who,
    Whois,
    Whowas,
    Motd,
    Lusers,
    Version,
    Admin,
    Info,

    // Operator
    Oper,
    Kill,
    Wallops,

    // Away
    Away,

    // User queries
    Userhost,
    Ison,

    // Server queries (Admin and Info already exist above under Queries)
    Stats,
    Time,
    Links,
    Map,
    Trace,

    // Numeric reply (three-digit code)
    Numeric(u16),

    // Unknown/unhandled command
    Unknown(String),
}

impl Command {
    pub fn from_str_lossy(s: &str) -> Self {
        // Try numeric first
        if s.len() == 3 {
            if let Ok(n) = s.parse::<u16>() {
                return Command::Numeric(n);
            }
        }

        match s.to_ascii_uppercase().as_str() {
            "CAP" => Command::Cap,
            "NICK" => Command::Nick,
            "USER" => Command::User,
            "PASS" => Command::Pass,
            "PING" => Command::Ping,
            "PONG" => Command::Pong,
            "QUIT" => Command::Quit,
            "ERROR" => Command::Error,
            "BATCH" => Command::Batch,
            "JOIN" => Command::Join,
            "PART" => Command::Part,
            "TOPIC" => Command::Topic,
            "KICK" => Command::Kick,
            "INVITE" => Command::Invite,
            "NAMES" => Command::Names,
            "LIST" => Command::List,
            "PRIVMSG" => Command::Privmsg,
            "NOTICE" => Command::Notice,
            "MODE" => Command::Mode,
            "WHO" => Command::Who,
            "WHOIS" => Command::Whois,
            "WHOWAS" => Command::Whowas,
            "MOTD" => Command::Motd,
            "LUSERS" => Command::Lusers,
            "VERSION" => Command::Version,
            "ADMIN" => Command::Admin,
            "INFO" => Command::Info,
            "OPER" => Command::Oper,
            "KILL" => Command::Kill,
            "WALLOPS" => Command::Wallops,
            "AWAY" => Command::Away,
            "USERHOST" => Command::Userhost,
            "ISON" => Command::Ison,
            "STATS" => Command::Stats,
            "TIME" => Command::Time,
            "LINKS" => Command::Links,
            "MAP" => Command::Map,
            "TRACE" => Command::Trace,
            other => Command::Unknown(other.to_string()),
        }
    }
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Command::Cap => write!(f, "CAP"),
            Command::Nick => write!(f, "NICK"),
            Command::User => write!(f, "USER"),
            Command::Pass => write!(f, "PASS"),
            Command::Ping => write!(f, "PING"),
            Command::Pong => write!(f, "PONG"),
            Command::Quit => write!(f, "QUIT"),
            Command::Error => write!(f, "ERROR"),
            Command::Batch => write!(f, "BATCH"),
            Command::Join => write!(f, "JOIN"),
            Command::Part => write!(f, "PART"),
            Command::Topic => write!(f, "TOPIC"),
            Command::Kick => write!(f, "KICK"),
            Command::Invite => write!(f, "INVITE"),
            Command::Names => write!(f, "NAMES"),
            Command::List => write!(f, "LIST"),
            Command::Privmsg => write!(f, "PRIVMSG"),
            Command::Notice => write!(f, "NOTICE"),
            Command::Mode => write!(f, "MODE"),
            Command::Who => write!(f, "WHO"),
            Command::Whois => write!(f, "WHOIS"),
            Command::Whowas => write!(f, "WHOWAS"),
            Command::Motd => write!(f, "MOTD"),
            Command::Lusers => write!(f, "LUSERS"),
            Command::Version => write!(f, "VERSION"),
            Command::Admin => write!(f, "ADMIN"),
            Command::Info => write!(f, "INFO"),
            Command::Oper => write!(f, "OPER"),
            Command::Kill => write!(f, "KILL"),
            Command::Wallops => write!(f, "WALLOPS"),
            Command::Away => write!(f, "AWAY"),
            Command::Userhost => write!(f, "USERHOST"),
            Command::Ison => write!(f, "ISON"),
            Command::Stats => write!(f, "STATS"),
            Command::Time => write!(f, "TIME"),
            Command::Links => write!(f, "LINKS"),
            Command::Map => write!(f, "MAP"),
            Command::Trace => write!(f, "TRACE"),
            Command::Numeric(n) => write!(f, "{n:03}"),
            Command::Unknown(s) => write!(f, "{s}"),
        }
    }
}
