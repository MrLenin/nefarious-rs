use std::fmt;

use crate::command::Command;

/// A parsed IRC message per RFC 1459 / IRCv3.
///
/// Format: `[@tags] [:source] <command> [params...] [:trailing]`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    /// IRCv3 message tags (key=value pairs).
    pub tags: Vec<Tag>,
    /// Message source (nick!user@host or server name).
    pub source: Option<String>,
    /// The IRC command.
    pub command: Command,
    /// Command parameters (trailing param included as last element).
    pub params: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: Option<String>,
}

impl Message {
    /// Create a new message with no tags or source.
    pub fn new(command: Command, params: Vec<String>) -> Self {
        Self {
            tags: Vec::new(),
            source: None,
            command,
            params,
        }
    }

    /// Create a new message with a source prefix.
    pub fn with_source(source: impl Into<String>, command: Command, params: Vec<String>) -> Self {
        Self {
            tags: Vec::new(),
            source: Some(source.into()),
            command,
            params,
        }
    }

    /// Parse an IRC message from a string.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim_end_matches(|c| c == '\r' || c == '\n');
        if input.is_empty() {
            return None;
        }

        let mut rest = input;
        let mut tags = Vec::new();
        let mut source = None;

        // Parse tags: @key=value;key2=value2
        if rest.starts_with('@') {
            let end = rest.find(' ')?;
            let tag_str = &rest[1..end];
            for part in tag_str.split(';') {
                if part.is_empty() {
                    continue;
                }
                if let Some(eq) = part.find('=') {
                    tags.push(Tag {
                        key: part[..eq].to_string(),
                        value: Some(unescape_tag_value(&part[eq + 1..])),
                    });
                } else {
                    tags.push(Tag {
                        key: part.to_string(),
                        value: None,
                    });
                }
            }
            rest = rest[end..].trim_start();
        }

        // Parse source: :prefix
        if rest.starts_with(':') {
            let end = rest.find(' ')?;
            source = Some(rest[1..end].to_string());
            rest = rest[end..].trim_start();
        }

        // Parse command
        let (cmd_str, remainder) = match rest.find(' ') {
            Some(idx) => (&rest[..idx], rest[idx..].trim_start()),
            None => (rest, ""),
        };

        if cmd_str.is_empty() {
            return None;
        }

        let command = Command::from_str_lossy(cmd_str);

        // Parse params
        let mut params = Vec::new();
        let mut rest = remainder;

        while !rest.is_empty() {
            if rest.starts_with(':') {
                // Trailing parameter — rest of line
                params.push(rest[1..].to_string());
                break;
            }

            match rest.find(' ') {
                Some(idx) => {
                    params.push(rest[..idx].to_string());
                    rest = rest[idx..].trim_start();
                }
                None => {
                    params.push(rest.to_string());
                    break;
                }
            }
        }

        Some(Message {
            tags,
            source,
            command,
            params,
        })
    }

    /// Get the trailing parameter (last param), if any.
    pub fn trailing(&self) -> Option<&str> {
        self.params.last().map(|s| s.as_str())
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Tags
        if !self.tags.is_empty() {
            write!(f, "@")?;
            for (i, tag) in self.tags.iter().enumerate() {
                if i > 0 {
                    write!(f, ";")?;
                }
                write!(f, "{}", tag.key)?;
                if let Some(ref val) = tag.value {
                    write!(f, "={}", escape_tag_value(val))?;
                }
            }
            write!(f, " ")?;
        }

        // Source
        if let Some(ref src) = self.source {
            write!(f, ":{src} ")?;
        }

        // Command
        write!(f, "{}", self.command)?;

        // Params. Always emit the last parameter with a leading `:` — this
        // is the convention every IRC server follows and it means the
        // wire format round-trips through parse/Display even when the
        // trailing param happens to not contain spaces (otherwise
        // `TOPIC #c :hello` would re-emit as `TOPIC #c hello`, which is
        // semantically equivalent but byte-wise different).
        let last_idx = self.params.len().saturating_sub(1);
        for (i, param) in self.params.iter().enumerate() {
            if i == last_idx {
                write!(f, " :{param}")?;
            } else {
                write!(f, " {param}")?;
            }
        }

        Ok(())
    }
}

fn unescape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(':') => result.push(';'),
                Some('s') => result.push(' '),
                Some('\\') => result.push('\\'),
                Some('r') => result.push('\r'),
                Some('n') => result.push('\n'),
                Some(other) => result.push(other),
                None => {}
            }
        } else {
            result.push(c);
        }
    }
    result
}

fn escape_tag_value(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ';' => result.push_str("\\:"),
            ' ' => result.push_str("\\s"),
            '\\' => result.push_str("\\\\"),
            '\r' => result.push_str("\\r"),
            '\n' => result.push_str("\\n"),
            _ => result.push(c),
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple() {
        let msg = Message::parse("NICK foo").unwrap();
        assert_eq!(msg.command, Command::Nick);
        assert_eq!(msg.params, vec!["foo"]);
        assert!(msg.source.is_none());
    }

    #[test]
    fn parse_with_source() {
        let msg = Message::parse(":nick!user@host PRIVMSG #channel :hello world").unwrap();
        assert_eq!(msg.source.as_deref(), Some("nick!user@host"));
        assert_eq!(msg.command, Command::Privmsg);
        assert_eq!(msg.params, vec!["#channel", "hello world"]);
    }

    #[test]
    fn parse_with_tags() {
        let msg =
            Message::parse("@time=2024-01-01T00:00:00Z :server NOTICE * :hello").unwrap();
        assert_eq!(msg.tags.len(), 1);
        assert_eq!(msg.tags[0].key, "time");
        assert_eq!(
            msg.tags[0].value.as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
    }

    #[test]
    fn parse_numeric() {
        let msg = Message::parse(":server 001 nick :Welcome").unwrap();
        assert_eq!(msg.command, Command::Numeric(1));
        assert_eq!(msg.params, vec!["nick", "Welcome"]);
    }

    #[test]
    fn roundtrip() {
        let original = ":server PRIVMSG #test :hello world";
        let msg = Message::parse(original).unwrap();
        assert_eq!(msg.to_string(), original);
    }

    #[test]
    fn parse_no_trailing() {
        let msg = Message::parse("MODE #channel +o nick").unwrap();
        assert_eq!(msg.command, Command::Mode);
        assert_eq!(msg.params, vec!["#channel", "+o", "nick"]);
    }

    #[test]
    fn parse_empty_trailing() {
        let msg = Message::parse("TOPIC #channel :").unwrap();
        assert_eq!(msg.command, Command::Topic);
        assert_eq!(msg.params, vec!["#channel", ""]);
    }
}
