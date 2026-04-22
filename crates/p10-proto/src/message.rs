use crate::token::P10Token;

/// A parsed P10 server-to-server message.
///
/// Format: `[@<tags>] [<origin>] <token> [<params>...] [:<trailing>]`
///
/// Origin is a numeric prefix: 2 chars for server, 5 chars for user.
/// During handshake (PASS/SERVER), there is no origin.
///
/// IRCv3 message tags can prefix the line (`@k1=v1;k2;k3=v3 …`).
/// nefarious2 also ships a compact P10-native form
/// `@A<time_base64_7><msgid_14>` — auto-detected by the absence of
/// `=`. Both forms populate `tag_time_ms` and `tag_msgid` so handlers
/// can propagate them onto the local broadcast's SourceInfo without
/// branching on encoding.
#[derive(Debug, Clone)]
pub struct P10Message {
    /// Origin numeric (2 chars = server, 5 chars = user, None = no prefix).
    pub origin: Option<String>,
    /// The P10 token/command.
    pub token: P10Token,
    /// Parameters (trailing included as last element).
    pub params: Vec<String>,
    /// `time` tag decoded as epoch milliseconds, when the inbound
    /// line carried one. Verbose `@time=<iso>` is parsed via
    /// iso-to-ms; compact `@A<time_7>...` is base64-decoded.
    pub tag_time_ms: Option<u64>,
    /// `msgid` tag value, when present.
    pub tag_msgid: Option<String>,
}

impl P10Message {
    /// Create a message with no origin (for handshake messages like PASS/SERVER).
    pub fn new(token: P10Token, params: Vec<String>) -> Self {
        Self {
            origin: None,
            token,
            params,
            tag_time_ms: None,
            tag_msgid: None,
        }
    }

    /// Create a message with a server or user numeric origin.
    pub fn with_origin(origin: impl Into<String>, token: P10Token, params: Vec<String>) -> Self {
        Self {
            origin: Some(origin.into()),
            token,
            params,
            tag_time_ms: None,
            tag_msgid: None,
        }
    }

    /// Parse a raw P10 line into a message.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim_end_matches(|c| c == '\r' || c == '\n');
        if input.is_empty() {
            return None;
        }

        let mut rest = input;
        let mut origin = None;
        let mut tag_time_ms: Option<u64> = None;
        let mut tag_msgid: Option<String> = None;

        // IRCv3 message tags prefix: `@<tags> ...`. nefarious2 emits
        // the compact form `@A<time_b64_7><msgid_14>` (no `=`); other
        // IRCv3 peers emit `@key=value;key=value`. Auto-detect by the
        // presence of `=` in the tag block (mirrors parse.c:1708).
        if rest.starts_with('@') {
            if let Some(space) = rest.find(' ') {
                let tag_block = &rest[1..space]; // skip the '@'
                if tag_block.contains('=') {
                    // Verbose: semicolon-separated key=value pairs.
                    for tag in tag_block.split(';') {
                        if let Some((k, v)) = tag.split_once('=') {
                            match k {
                                "time" => {
                                    tag_time_ms = parse_iso_to_ms(v);
                                }
                                "msgid" => tag_msgid = Some(v.to_string()),
                                _ => {}
                            }
                        }
                    }
                } else if tag_block.len() >= 22 && tag_block.starts_with('A') {
                    // Compact: A + 7 chars time + 14+ chars msgid.
                    let time_b64 = &tag_block[1..8];
                    let msgid = &tag_block[8..];
                    tag_time_ms = Some(crate::numeric::base64toint_64(time_b64));
                    // Take the first 14 chars as the primary msgid;
                    // a trailing multi-msgid block is carried but we
                    // only surface the head for now.
                    tag_msgid = Some(msgid.chars().take(14).collect());
                }
                rest = rest[space..].trim_start();
            } else {
                return None;
            }
        }

        // Check for origin prefix
        // In P10, the origin is NOT prefixed with ':' — it's just the numeric.
        // But during handshake, PASS and SERVER have no prefix.
        // Heuristic: if first word is 1-5 chars of base64 and second word looks like a token, treat first as origin.
        // The handshake messages (PASS, SERVER) are sent without prefix.
        let first_space = rest.find(' ')?;
        let first_word = &rest[..first_space];
        let after_first = rest[first_space..].trim_start();

        // Detect whether first word is a numeric prefix or a command
        if is_likely_numeric(first_word) && !after_first.is_empty() {
            origin = Some(first_word.to_string());
            rest = after_first;
        }
        // else: first word is the command/token itself (no prefix)

        // Parse token
        let (token_str, remainder) = match rest.find(' ') {
            Some(idx) => (&rest[..idx], rest[idx..].trim_start()),
            None => (rest, ""),
        };

        if token_str.is_empty() {
            return None;
        }

        let token = P10Token::from_token(token_str);

        // Parse params
        let mut params = Vec::new();
        let mut rest = remainder;

        while !rest.is_empty() {
            if rest.starts_with(':') {
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

        Some(P10Message {
            origin,
            token,
            params,
            tag_time_ms,
            tag_msgid,
        })
    }

    /// Serialize to a P10 wire format string (without \r\n).
    pub fn to_wire(&self) -> String {
        let mut out = String::with_capacity(128);

        if let Some(ref origin) = self.origin {
            out.push_str(origin);
            out.push(' ');
        }

        out.push_str(self.token.to_token());

        for (i, param) in self.params.iter().enumerate() {
            let is_last = i == self.params.len() - 1;
            if is_last && (param.contains(' ') || param.starts_with(':') || param.is_empty()) {
                out.push(' ');
                out.push(':');
                out.push_str(param);
            } else {
                out.push(' ');
                out.push_str(param);
            }
        }

        out
    }

    /// Check if the origin is a server numeric (2 chars).
    pub fn is_server_origin(&self) -> bool {
        self.origin.as_ref().is_some_and(|o| o.len() <= 2)
    }

    /// Check if the origin is a user numeric (3-5 chars).
    pub fn is_user_origin(&self) -> bool {
        self.origin.as_ref().is_some_and(|o| o.len() >= 3)
    }

    /// Serialize for handshake (PASS/SERVER) — always uses trailing colon on last param.
    /// C Nefarious sends `PASS :password` and `SERVER ... :description`.
    pub fn to_wire_handshake(&self) -> String {
        let mut out = String::with_capacity(128);

        if let Some(ref origin) = self.origin {
            out.push_str(origin);
            out.push(' ');
        }

        // Use full command names for handshake, not tokens
        let cmd = match self.token {
            P10Token::Pass => "PASS",
            P10Token::Server => "SERVER",
            _ => self.token.to_token(),
        };
        out.push_str(cmd);

        for (i, param) in self.params.iter().enumerate() {
            out.push(' ');
            if i == self.params.len() - 1 {
                out.push(':');
            }
            out.push_str(param);
        }

        out
    }
}

/// Heuristic: is this string likely a P10 numeric prefix?
/// P10 numerics are 1-5 chars from the base64 alphabet.
/// Commands like PASS, SERVER, ERROR are NOT numerics.
fn is_likely_numeric(s: &str) -> bool {
    if s.is_empty() || s.len() > 5 {
        return false;
    }
    // If it's all uppercase letters and len >= 3, it might be a command
    // P10 numerics use mixed case + digits + []
    // Quick check: if ALL chars are A-Z, it's probably a command, not a numeric
    let all_upper = s.bytes().all(|b| b.is_ascii_uppercase());
    if all_upper && s.len() >= 2 {
        // Could be a 2-char token like "AB" (numeric) or "EB" (token)
        // Check if it matches known non-prefixed commands
        match s {
            "PASS" | "SERVER" | "ERROR" | "PING" | "PONG" => return false,
            _ => {}
        }
        // 2-char all-uppercase could be either numeric or token.
        // In practice, during burst the origin is always present.
        // We rely on context: PASS/SERVER at handshake have no prefix.
    }
    // Check all chars are valid base64
    s.bytes().all(|b| is_base64_char(b))
}

fn is_base64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'[' || b == b']'
}

/// Parse ISO 8601 (`YYYY-MM-DDTHH:MM:SS.sssZ`) to epoch milliseconds.
/// Returns `None` on malformed input; we use this to back-convert the
/// verbose `@time=` tag form (which nefarious2 still accepts) into
/// the same u64 our compact-path produces.
fn parse_iso_to_ms(s: &str) -> Option<u64> {
    // Minimal handwritten parser — avoids pulling chrono into the
    // p10-proto crate for one conversion. Matches the format we
    // ourselves emit (server_time tag): 24 chars, fixed layout.
    if s.len() < 20 {
        return None;
    }
    let b = s.as_bytes();
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let yr: i64 = s[0..4].parse().ok()?;
    let mo: u32 = s[5..7].parse().ok()?;
    let dy: u32 = s[8..10].parse().ok()?;
    let hr: i64 = s[11..13].parse().ok()?;
    let mn: i64 = s[14..16].parse().ok()?;
    let sc: i64 = s[17..19].parse().ok()?;
    let ms: i64 = if s.len() >= 23 && b[19] == b'.' {
        s[20..23].parse().ok()?
    } else {
        0
    };

    // Days from 0000-03-01 to the given date (civil-from-ymd trick).
    let y = if mo <= 2 { yr - 1 } else { yr };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as i64;
    let m = mo as i64;
    let d = dy as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    let secs = days * 86400 + hr * 3600 + mn * 60 + sc;
    Some((secs * 1000 + ms) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pass() {
        let msg = P10Message::parse("PASS :secretpassword").unwrap();
        assert!(msg.origin.is_none());
        assert_eq!(msg.token, P10Token::Pass);
        assert_eq!(msg.params, vec!["secretpassword"]);
    }

    #[test]
    fn parse_server_handshake() {
        let msg = P10Message::parse(
            "SERVER irc.example.com 1 1609459200 1609545600 J10 ABAAC +h6 :Test Server",
        )
        .unwrap();
        assert!(msg.origin.is_none());
        assert_eq!(msg.token, P10Token::Server);
        assert_eq!(msg.params[0], "irc.example.com");
        assert_eq!(msg.params[1], "1");
        assert!(msg.params.last().unwrap() == "Test Server");
    }

    #[test]
    fn parse_nick_burst() {
        let msg = P10Message::parse(
            "AB N alice 1 1609545620 alice alice.example.com +i AAAAAA AB AAA :Alice User",
        )
        .unwrap();
        assert_eq!(msg.origin.as_deref(), Some("AB"));
        assert_eq!(msg.token, P10Token::Nick);
        assert_eq!(msg.params[0], "alice");
    }

    #[test]
    fn parse_burst() {
        let msg =
            P10Message::parse("AB B #test 1609545600 +nt ABAAB,ABAAC:o :%*!*@banned").unwrap();
        assert_eq!(msg.origin.as_deref(), Some("AB"));
        assert_eq!(msg.token, P10Token::Burst);
        assert_eq!(msg.params[0], "#test");
    }

    #[test]
    fn parse_privmsg() {
        let msg = P10Message::parse("ABAAB P #test :hello world").unwrap();
        assert_eq!(msg.origin.as_deref(), Some("ABAAB"));
        assert_eq!(msg.token, P10Token::Privmsg);
        assert_eq!(msg.params, vec!["#test", "hello world"]);
    }

    #[test]
    fn parse_end_of_burst() {
        let msg = P10Message::parse("AB EB").unwrap();
        assert_eq!(msg.origin.as_deref(), Some("AB"));
        assert_eq!(msg.token, P10Token::EndOfBurst);
        assert!(msg.params.is_empty());
    }

    #[test]
    fn parse_ping() {
        let msg = P10Message::parse("AB G :AC").unwrap();
        assert_eq!(msg.origin.as_deref(), Some("AB"));
        assert_eq!(msg.token, P10Token::Ping);
        assert_eq!(msg.params, vec!["AC"]);
    }

    #[test]
    fn serialize_roundtrip() {
        let msg = P10Message::with_origin(
            "AB",
            P10Token::Privmsg,
            vec!["#test".into(), "hello world".into()],
        );
        assert_eq!(msg.to_wire(), "AB P #test :hello world");
    }

    #[test]
    fn serialize_no_origin() {
        // PASS with trailing colon (password contains no space but convention uses trailing)
        let msg = P10Message::new(P10Token::Pass, vec!["secretpassword".into()]);
        // Single non-space param doesn't require trailing colon in generic serializer
        assert_eq!(msg.to_wire(), "PA secretpassword");
    }

    #[test]
    fn serialize_trailing_colon() {
        // When param has a space, trailing colon is required
        let msg = P10Message::new(P10Token::Pass, vec!["secret password".into()]);
        assert_eq!(msg.to_wire(), "PA :secret password");
    }

    #[test]
    fn serialize_server() {
        let msg = P10Message::new(
            P10Token::Server,
            vec![
                "irc.test.com".into(),
                "1".into(),
                "12345".into(),
                "12346".into(),
                "J10".into(),
                "ABAAC".into(),
                "+6".into(),
                "Test Server".into(),
            ],
        );
        let wire = msg.to_wire();
        assert!(wire.starts_with("S irc.test.com 1"));
        assert!(wire.ends_with(":Test Server"));
    }
}
