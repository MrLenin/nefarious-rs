use nom::{
    IResult, Parser,
    branch::alt,
    bytes::complete::{tag_no_case, take_while1},
    character::complete::{char, digit1, space0},
    combinator::{map, map_res, opt, recognize, value},
    multi::many0,
    sequence::pair,
};

/// A raw parsed block from ircd.conf.
#[derive(Debug, Clone)]
pub struct Block {
    pub kind: String,
    pub entries: Vec<Entry>,
}

/// A single entry within a config block.
#[derive(Debug, Clone)]
pub enum Entry {
    /// `key = value;`
    KeyValue(String, Value),
    /// `flag;` (bare identifier)
    Flag(String),
}

/// A configuration value.
#[derive(Debug, Clone)]
pub enum Value {
    String(String),
    Integer(i64),
    Boolean(bool),
    Duration(std::time::Duration),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Integer(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_duration(&self) -> Option<std::time::Duration> {
        match self {
            Value::Duration(d) => Some(*d),
            _ => None,
        }
    }

    pub fn as_u16(&self) -> Option<u16> {
        match self {
            Value::Integer(n) => u16::try_from(*n).ok(),
            Value::String(s) => s.parse().ok(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Whitespace & comments
// ---------------------------------------------------------------------------

fn ws(input: &str) -> IResult<&str, ()> {
    let mut rest = input;
    loop {
        let before = rest;
        // Skip whitespace
        rest = rest.trim_start();
        // Skip line comments
        if rest.starts_with('#') {
            if let Some(nl) = rest.find('\n') {
                rest = &rest[nl + 1..];
                continue;
            } else {
                rest = "";
                break;
            }
        }
        // Skip block comments
        if rest.starts_with("/*") {
            match rest.find("*/") {
                Some(end) => {
                    rest = &rest[end + 2..];
                    continue;
                }
                None => {
                    rest = "";
                    break;
                }
            }
        }
        if rest.len() == before.len() {
            break;
        }
    }
    Ok((rest, ()))
}

// ---------------------------------------------------------------------------
// Value parsers
// ---------------------------------------------------------------------------

fn quoted_string(input: &str) -> IResult<&str, String> {
    let (rest, _) = char('"').parse(input)?;
    let mut result = String::new();
    let mut chars = rest.char_indices();
    loop {
        match chars.next() {
            Some((_, '\\')) => {
                if let Some((_, c)) = chars.next() {
                    result.push(c);
                }
            }
            Some((i, '"')) => {
                return Ok((&rest[i + 1..], result));
            }
            Some((_, c)) => result.push(c),
            None => {
                return Err(nom::Err::Error(nom::error::Error::new(
                    input,
                    nom::error::ErrorKind::Char,
                )));
            }
        }
    }
}

fn boolean(input: &str) -> IResult<&str, bool> {
    alt((
        value(true, tag_no_case("yes")),
        value(true, tag_no_case("true")),
        value(false, tag_no_case("no")),
        value(false, tag_no_case("false")),
    ))
    .parse(input)
}

fn parse_u64(input: &str) -> IResult<&str, u64> {
    map_res(digit1, |s: &str| s.parse::<u64>()).parse(input)
}

fn duration(input: &str) -> IResult<&str, std::time::Duration> {
    let (rest, first_num) = parse_u64(input)?;
    let (rest, _) = space0.parse(rest)?;

    if let Ok((rest2, unit)) = time_unit(rest) {
        let mut total_secs = first_num * unit;
        let mut rest = rest2;
        loop {
            let (r, _) = space0.parse(rest)?;
            if let Ok((r2, num)) = parse_u64(r) {
                let (r3, _) = space0.parse(r2)?;
                if let Ok((r4, unit)) = time_unit(r3) {
                    total_secs += num * unit;
                    rest = r4;
                    continue;
                }
            }
            break;
        }
        Ok((rest, std::time::Duration::from_secs(total_secs)))
    } else {
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Tag,
        )))
    }
}

fn time_unit(input: &str) -> IResult<&str, u64> {
    alt((
        value(
            1u64,
            alt((
                tag_no_case("seconds"),
                tag_no_case("second"),
                tag_no_case("secs"),
                tag_no_case("sec"),
                tag_no_case("s"),
            )),
        ),
        value(
            60u64,
            alt((
                tag_no_case("minutes"),
                tag_no_case("minute"),
                tag_no_case("mins"),
                tag_no_case("min"),
            )),
        ),
        value(
            3600u64,
            alt((
                tag_no_case("hours"),
                tag_no_case("hour"),
                tag_no_case("hrs"),
                tag_no_case("hr"),
                tag_no_case("h"),
            )),
        ),
        value(
            86400u64,
            alt((tag_no_case("days"), tag_no_case("day"), tag_no_case("d"))),
        ),
    ))
    .parse(input)
}

fn integer(input: &str) -> IResult<&str, i64> {
    map_res(recognize(pair(opt(char('-')), digit1)), |s: &str| {
        s.parse::<i64>()
    })
    .parse(input)
}

fn identifier(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_alphanumeric() || c == '_' || c == '-' || c == '.').parse(input)
}

fn config_value(input: &str) -> IResult<&str, Value> {
    alt((
        map(duration, Value::Duration),
        map(boolean, Value::Boolean),
        map(quoted_string, Value::String),
        map(integer, Value::Integer),
        map(
            take_while1(|c: char| !c.is_whitespace() && c != ';' && c != '}'),
            |s: &str| Value::String(s.to_string()),
        ),
    ))
    .parse(input)
}

// ---------------------------------------------------------------------------
// Entry parsers
// ---------------------------------------------------------------------------

fn key_value_entry(input: &str) -> IResult<&str, Entry> {
    let (rest, _) = ws(input)?;
    let (rest, key) = identifier(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char('=').parse(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, val) = config_value(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char(';').parse(rest)?;
    Ok((rest, Entry::KeyValue(key.to_string(), val)))
}

fn flag_entry(input: &str) -> IResult<&str, Entry> {
    let (rest, _) = ws(input)?;
    let (rest, name) = identifier(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char(';').parse(rest)?;
    Ok((rest, Entry::Flag(name.to_string())))
}

fn entry(input: &str) -> IResult<&str, Entry> {
    alt((key_value_entry, flag_entry)).parse(input)
}

// ---------------------------------------------------------------------------
// Block parser
// ---------------------------------------------------------------------------

fn block(input: &str) -> IResult<&str, Block> {
    let (rest, _) = ws(input)?;
    let (rest, kind) = identifier(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char('{').parse(rest)?;
    let (rest, entries) = many0(entry).parse(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char('}').parse(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char(';').parse(rest)?;

    Ok((
        rest,
        Block {
            kind: kind.to_string(),
            entries,
        },
    ))
}

fn include_directive(input: &str) -> IResult<&str, String> {
    let (rest, _) = ws(input)?;
    let (rest, _) = tag_no_case("include").parse(rest)?;
    // Must have whitespace after "include"
    if !rest.starts_with(char::is_whitespace) {
        return Err(nom::Err::Error(nom::error::Error::new(
            rest,
            nom::error::ErrorKind::Space,
        )));
    }
    let (rest, _) = ws(rest)?;
    let (rest, path) = quoted_string(rest)?;
    let (rest, _) = ws(rest)?;
    let (rest, _) = char(';').parse(rest)?;
    Ok((rest, path))
}

/// Top-level item: either an include or a block.
#[derive(Debug, Clone)]
pub enum TopLevel {
    Block(Block),
    Include(String),
}

fn top_level_item(input: &str) -> IResult<&str, TopLevel> {
    alt((
        map(include_directive, TopLevel::Include),
        map(block, TopLevel::Block),
    ))
    .parse(input)
}

/// Parse an entire ircd.conf file into top-level items.
pub fn parse_config(input: &str) -> Result<Vec<TopLevel>, String> {
    let mut rest = input;
    let mut items = Vec::new();

    loop {
        match ws(rest) {
            Ok((r, _)) => rest = r,
            Err(_) => break,
        }

        if rest.is_empty() {
            break;
        }

        match top_level_item(rest) {
            Ok((r, item)) => {
                items.push(item);
                rest = r;
            }
            Err(e) => {
                let consumed = input.len() - rest.len();
                let line_num = input[..consumed].lines().count() + 1;
                let preview: String = rest.chars().take(40).collect();
                return Err(format!(
                    "parse error near line {line_num}: {e}\n  near: \"{preview}...\""
                ));
            }
        }
    }

    Ok(items)
}

// ---------------------------------------------------------------------------
// Block accessor helpers
// ---------------------------------------------------------------------------

impl Block {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find_map(|e| match e {
            Entry::KeyValue(k, v) if k.eq_ignore_ascii_case(key) => Some(v),
            _ => None,
        })
    }

    pub fn get_all(&self, key: &str) -> Vec<&Value> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                Entry::KeyValue(k, v) if k.eq_ignore_ascii_case(key) => Some(v),
                _ => None,
            })
            .collect()
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }

    pub fn has_flag(&self, name: &str) -> bool {
        self.entries.iter().any(|e| matches!(e, Entry::Flag(f) if f.eq_ignore_ascii_case(name)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_port_block() {
        let input = r#"
            Port {
                port = 6667;
                ssl = no;
            };
        "#;
        let items = parse_config(input).unwrap();
        assert_eq!(items.len(), 1);
        if let TopLevel::Block(b) = &items[0] {
            assert_eq!(b.kind, "Port");
            assert_eq!(b.get_i64("port"), Some(6667));
            assert_eq!(b.get_bool("ssl"), Some(false));
        } else {
            panic!("expected block");
        }
    }

    #[test]
    fn parse_general_block() {
        let input = r#"
            General {
                name = "test.server.net";
                description = "Test Server";
                numeric = 1;
            };
        "#;
        let items = parse_config(input).unwrap();
        let b = match &items[0] {
            TopLevel::Block(b) => b,
            _ => panic!("expected block"),
        };
        assert_eq!(b.get_str("name"), Some("test.server.net"));
        assert_eq!(b.get_str("description"), Some("Test Server"));
        assert_eq!(b.get_i64("numeric"), Some(1));
    }

    #[test]
    fn parse_duration_value() {
        let input = r#"
            Class {
                name = "Server";
                pingfreq = 1 minutes 30 seconds;
                sendq = 9000000;
            };
        "#;
        let items = parse_config(input).unwrap();
        let b = match &items[0] {
            TopLevel::Block(b) => b,
            _ => panic!("expected block"),
        };
        assert_eq!(
            b.get("pingfreq").unwrap().as_duration(),
            Some(std::time::Duration::from_secs(90))
        );
    }

    #[test]
    fn parse_flag() {
        let input = r#"
            Connect {
                name = "hub.server.net";
                hub;
                autoconnect = yes;
            };
        "#;
        let items = parse_config(input).unwrap();
        let b = match &items[0] {
            TopLevel::Block(b) => b,
            _ => panic!("expected block"),
        };
        assert!(b.has_flag("hub"));
        assert!(!b.has_flag("leaf"));
        assert_eq!(b.get_bool("autoconnect"), Some(true));
    }

    #[test]
    fn parse_with_comments() {
        let input = r#"
            # This is a comment
            General {
                name = "test.net";   # inline comment
                numeric = 42;
            };
        "#;
        let items = parse_config(input).unwrap();
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn parse_include() {
        let input = r#"include "local.conf";"#;
        let items = parse_config(input).unwrap();
        assert_eq!(items.len(), 1);
        match &items[0] {
            TopLevel::Include(p) => assert_eq!(p, "local.conf"),
            _ => panic!("expected include"),
        }
    }

    #[test]
    fn parse_multiple_blocks() {
        let input = r#"
            General { name = "test"; numeric = 1; };
            Port { port = 6667; ssl = no; };
            Port { port = 6697; ssl = yes; };
        "#;
        let items = parse_config(input).unwrap();
        assert_eq!(items.len(), 3);
    }
}
