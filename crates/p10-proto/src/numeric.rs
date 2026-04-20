/// P10 base64 alphabet: A-Z a-z 0-9 [ ]
const ENCODE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]";

/// Decode table: ASCII byte → 6-bit value (255 = invalid).
const DECODE: [u8; 128] = {
    let mut table = [255u8; 128];
    let mut i = 0;
    while i < 64 {
        table[ENCODE[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Encode an integer into P10 base64, writing `count` characters.
pub fn inttobase64(value: u32, count: usize) -> String {
    let mut buf = vec![b'A'; count];
    let mut v = value;
    let mut i = count;
    while i > 0 {
        i -= 1;
        buf[i] = ENCODE[(v & 63) as usize];
        v >>= 6;
    }
    // Safety: all bytes are from ENCODE which is ASCII
    unsafe { String::from_utf8_unchecked(buf) }
}

/// Decode P10 base64 string to integer.
pub fn base64toint(s: &str) -> u32 {
    let mut v = 0u32;
    for &b in s.as_bytes() {
        if (b as usize) < 128 {
            let d = DECODE[b as usize];
            if d < 64 {
                v = (v << 6) | d as u32;
            }
        }
    }
    v
}

/// A P10 server numeric (2 base64 chars, 0-4095).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerNumeric(pub u16);

impl ServerNumeric {
    /// Decode from a 2-character base64 string.
    pub fn from_str(s: &str) -> Option<Self> {
        if s.len() >= 2 {
            Some(Self(base64toint(&s[..2]) as u16))
        } else {
            None
        }
    }

    /// Encode to a 2-character base64 string.
    pub fn to_string(&self) -> String {
        inttobase64(self.0 as u32, 2)
    }
}

impl std::fmt::Debug for ServerNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerNumeric({}, \"{}\")", self.0, self.to_string())
    }
}

impl std::fmt::Display for ServerNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// A P10 client numeric (server 2 chars + client 3 chars = 5 chars total).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientNumeric {
    pub server: ServerNumeric,
    pub client: u32, // 0-262143 (3 base64 chars = 18 bits)
}

impl ClientNumeric {
    /// Decode from a 5-character base64 string (YYXXX).
    pub fn from_str(s: &str) -> Option<Self> {
        if s.len() >= 5 {
            let server = ServerNumeric::from_str(&s[..2])?;
            let client = base64toint(&s[2..5]);
            Some(Self { server, client })
        } else {
            None
        }
    }

    /// Encode to a 5-character base64 string.
    pub fn to_string(&self) -> String {
        format!("{}{}", self.server, inttobase64(self.client, 3))
    }
}

impl std::fmt::Debug for ClientNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientNumeric(\"{}\")", self.to_string())
    }
}

impl std::fmt::Display for ClientNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Encode an IPv4 address to P10 base64 (6 characters).
pub fn ipv4_to_base64(ip: std::net::Ipv4Addr) -> String {
    let bits = u32::from(ip);
    inttobase64(bits, 6)
}

/// Decode P10 base64 (6 characters) to IPv4 address.
pub fn base64_to_ipv4(s: &str) -> Option<std::net::Ipv4Addr> {
    if s.len() == 6 {
        Some(std::net::Ipv4Addr::from(base64toint(s)))
    } else {
        None
    }
}

/// Encode a numeric capacity mask (e.g., max clients) to base64.
/// The C code uses 3+ chars depending on capacity.
/// For our purposes, 3 chars covers up to 262143 clients.
pub fn capacity_to_base64(max_clients: u32) -> String {
    // C code: SetYXXCapacity stores the mask as base64
    // Capacity is stored as a mask (next power of 2 - 1)
    let mask = max_clients.next_power_of_two() - 1;
    // Determine needed chars: 1 char = 64, 2 = 4096, 3 = 262144
    if mask < 64 {
        inttobase64(mask, 1)
    } else if mask < 4096 {
        inttobase64(mask, 2)
    } else {
        inttobase64(mask, 3)
    }
}

/// Parse a numeric capacity string from a SERVER message.
/// Returns (server_numeric_str, capacity_mask).
/// Format: "YYXXX" where YY is server numeric, XXX is capacity.
/// Or "YY" + capacity chars of variable length.
pub fn parse_server_numeric_capacity(s: &str) -> Option<(ServerNumeric, u32)> {
    if s.len() < 3 {
        return None;
    }
    let server = ServerNumeric::from_str(&s[..2])?;
    let mask = base64toint(&s[2..]);
    Some((server, mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        assert_eq!(inttobase64(0, 2), "AA");
        assert_eq!(inttobase64(1, 2), "AB");
        assert_eq!(inttobase64(63, 2), "A]");
        assert_eq!(inttobase64(64, 2), "BA");
        assert_eq!(inttobase64(4095, 2), "]]");

        assert_eq!(base64toint("AA"), 0);
        assert_eq!(base64toint("AB"), 1);
        assert_eq!(base64toint("BA"), 64);
        assert_eq!(base64toint("]]"), 4095);
    }

    #[test]
    fn base64_three_chars() {
        assert_eq!(inttobase64(0, 3), "AAA");
        assert_eq!(inttobase64(262143, 3), "]]]");
        assert_eq!(base64toint("AAA"), 0);
        assert_eq!(base64toint("]]]"), 262143);
    }

    #[test]
    fn server_numeric() {
        let sn = ServerNumeric(0);
        assert_eq!(sn.to_string(), "AA");

        let sn = ServerNumeric::from_str("AB").unwrap();
        assert_eq!(sn.0, 1);

        let sn = ServerNumeric::from_str("]]").unwrap();
        assert_eq!(sn.0, 4095);
    }

    #[test]
    fn client_numeric() {
        let cn = ClientNumeric::from_str("ABAAB").unwrap();
        assert_eq!(cn.server.0, 1); // AB = 1
        assert_eq!(cn.client, 1); // AAB = 1
        assert_eq!(cn.to_string(), "ABAAB");
    }

    #[test]
    fn client_numeric_roundtrip() {
        let cn = ClientNumeric {
            server: ServerNumeric(42),
            client: 100,
        };
        let s = cn.to_string();
        let cn2 = ClientNumeric::from_str(&s).unwrap();
        assert_eq!(cn, cn2);
    }

    #[test]
    fn ipv4_encoding() {
        let ip = std::net::Ipv4Addr::new(127, 0, 0, 1);
        let encoded = ipv4_to_base64(ip);
        let decoded = base64_to_ipv4(&encoded).unwrap();
        assert_eq!(decoded, ip);
    }

    #[test]
    fn ipv4_zeros() {
        let ip = std::net::Ipv4Addr::new(0, 0, 0, 0);
        assert_eq!(ipv4_to_base64(ip), "AAAAAA");
    }

    #[test]
    fn capacity_parsing() {
        // Server AB with capacity mask AAC (= 2)
        let (sn, mask) = parse_server_numeric_capacity("ABAAC").unwrap();
        assert_eq!(sn.0, 1);
        assert_eq!(mask, 2);
    }
}
