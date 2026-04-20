//! RFC 1459 casefolding for IRC identifiers (nicks, channels, masks).
//!
//! Under rfc1459 casemapping — what Nefarious and most traditional IRCds
//! advertise via `CASEMAPPING=rfc1459` — the characters `{|}~` are the
//! lowercase forms of `[\]^`. This is a historical artefact of the Swedish
//! 7-bit charset that shaped early IRC nick rules and it is **load-bearing**:
//! two servers that disagree on casefolding will disagree on whether
//! `foo{bar` and `foo[bar` collide, guaranteeing netsplits on P10 burst.
//!
//! Use these helpers for every IRC identifier comparison. Plain
//! `to_ascii_lowercase` / `eq_ignore_ascii_case` is only appropriate for
//! non-IRC strings like config keys.

/// RFC 1459 lowercase map: A-Z → a-z plus `[\]^` → `{|}~`.
#[inline]
pub const fn to_lower(b: u8) -> u8 {
    match b {
        b'A'..=b'Z' => b + 32,
        b'[' => b'{',
        b'\\' => b'|',
        b']' => b'}',
        b'^' => b'~',
        other => other,
    }
}

/// Lowercase an IRC identifier per rfc1459.
///
/// `to_lower` only rewrites bytes in the ASCII range, so UTF-8 continuation
/// bytes (>=0x80) pass through untouched — the result is always valid UTF-8
/// when the input is.
pub fn irc_casefold(s: &str) -> String {
    let bytes: Vec<u8> = s.as_bytes().iter().map(|&b| to_lower(b)).collect();
    // Safety: input was valid UTF-8 and we only mapped ASCII bytes to other
    // ASCII bytes; UTF-8 structure is preserved.
    unsafe { String::from_utf8_unchecked(bytes) }
}

/// Case-insensitive equality per rfc1459.
pub fn irc_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes())
        .all(|(&x, &y)| to_lower(x) == to_lower(y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_lowercase() {
        assert_eq!(irc_casefold("Alice"), "alice");
        assert_eq!(irc_casefold("#TEST"), "#test");
    }

    #[test]
    fn rfc1459_special_chars() {
        assert_eq!(irc_casefold("Foo[bar]"), "foo{bar}");
        assert_eq!(irc_casefold(r"A\B"), "a|b");
        assert_eq!(irc_casefold("X^Y"), "x~y");
    }

    #[test]
    fn equality() {
        assert!(irc_eq("foo{bar", "FOO[BAR"));
        assert!(irc_eq("#Chan", "#chan"));
        assert!(!irc_eq("alice", "bob"));
        assert!(!irc_eq("alice", "alicex"));
    }

    #[test]
    fn lower_tildes_and_backtick_unchanged() {
        // ` and _ have no special rfc1459 mapping
        assert_eq!(irc_casefold("A`_b"), "a`_b");
    }

    #[test]
    fn non_ascii_bytes_pass_through() {
        // rfc1459 says nothing about >0x7F; leave untouched.
        let s = "café";
        assert_eq!(irc_casefold(s), "café");
    }
}
