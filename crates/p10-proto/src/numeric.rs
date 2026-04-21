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
    pub fn encode(&self) -> String {
        inttobase64(self.0 as u32, 2)
    }
}

impl std::fmt::Debug for ServerNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ServerNumeric({}, \"{}\")", self.0, self.encode())
    }
}

impl std::fmt::Display for ServerNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
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
    pub fn encode(&self) -> String {
        format!("{}{}", self.server, inttobase64(self.client, 3))
    }
}

impl std::fmt::Debug for ClientNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientNumeric(\"{}\")", self.encode())
    }
}

impl std::fmt::Display for ClientNumeric {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.server, inttobase64(self.client, 3))
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

/// Encode any IP address into the format used on the P10 wire.
///
/// Matches `iptobase64` in `nefarious2/ircd/numnicks.c:475` when the peer
/// advertises `+6` (IPv6-capable):
///   * IPv4 and IPv4-mapped IPv6 (`::ffff:a.b.c.d`) collapse to the 6-char
///     32-bit form, for backwards compatibility with legacy peers.
///   * Otherwise each 16-bit IPv6 segment is encoded as 3 base64 chars,
///     with the longest run of zero segments replaced by `_`.
pub fn ip_to_base64(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => ipv4_to_base64(v4),
        std::net::IpAddr::V6(v6) => {
            // IPv4-mapped (::ffff:a.b.c.d) or IPv4-compatible (::a.b.c.d)
            // both round-trip through the 32-bit form.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return ipv4_to_base64(v4);
            }

            let segs = v6.segments();

            let mut out = String::with_capacity(25);
            // Leading non-zero segments are emitted literally.
            let mut i = 0;
            while i < 8 && segs[i] != 0 {
                out.push_str(&inttobase64(segs[i] as u32, 3));
                i += 1;
            }
            let zero_start = i;

            // Find the longest run of zero segments from `zero_start` onward.
            let mut max_start = zero_start;
            let mut max_len = 0usize;
            let mut curr_start = zero_start;
            let mut curr_len = 0usize;
            for j in zero_start..8 {
                if segs[j] == 0 {
                    if curr_len == 0 {
                        curr_start = j;
                    }
                    curr_len += 1;
                    if curr_len > max_len {
                        max_start = curr_start;
                        max_len = curr_len;
                    }
                } else {
                    curr_len = 0;
                }
            }

            // Emit the remainder, collapsing the longest zero run to `_`.
            let mut ii = zero_start;
            while ii < 8 {
                if ii == max_start && max_len > 0 {
                    out.push('_');
                    ii += max_len;
                } else {
                    out.push_str(&inttobase64(segs[ii] as u32, 3));
                    ii += 1;
                }
            }

            out
        }
    }
}

/// Encode a numeric capacity mask (e.g., max clients) to base64.
///
/// **Always 3 characters** to match C nefarious2
/// (`ircd/numnicks.c::SetYXXCapacity`, which calls
/// `inttobase64(…, 3)` unconditionally). The peer's parser
/// (`SetServerYXX`, `numnicks.c:274`) checks `strlen(yxx) == 5` to
/// pick 2-char numeric + 3-char capacity; any other length triggers
/// the legacy 1-char numeric + 2-char capacity fallback, at which
/// point our server is registered under the wrong slot and burst
/// cross-references fail silently.
///
/// The input is the max client count; we emit the mask
/// (next_power_of_two - 1) packed into 3 base64 chars (18 bits, up
/// to 262,143 slots — matching the server-side client-numeric cap).
pub fn capacity_to_base64(max_clients: u32) -> String {
    let mask = max_clients.next_power_of_two() - 1;
    inttobase64(mask, 3)
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
    fn ipv6_all_zeros_collapses_to_underscore() {
        let ip: std::net::Ipv6Addr = "::".parse().unwrap();
        // All eight segments are zero → one _ replaces them all.
        assert_eq!(ip_to_base64(std::net::IpAddr::V6(ip)), "_");
    }

    #[test]
    fn ipv6_mapped_ipv4_uses_v4_form() {
        let v6: std::net::Ipv6Addr = "::ffff:127.0.0.1".parse().unwrap();
        let direct = ipv4_to_base64(std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ip_to_base64(std::net::IpAddr::V6(v6)), direct);
    }

    #[test]
    fn ipv6_compresses_longest_zero_run() {
        // 2001:0db8::8a2e:0370:7334 — three zero segments get the _.
        let ip: std::net::Ipv6Addr = "2001:db8::8a2e:370:7334".parse().unwrap();
        let s = ip_to_base64(std::net::IpAddr::V6(ip));
        // 2001 db8 _ 8a2e 0370 7334 → 3+3 + 1 + 3+3+3 = 16 chars
        assert_eq!(s.len(), 16);
        assert!(s.contains('_'));
    }

    #[test]
    fn ipv6_no_zero_run_no_underscore() {
        let ip: std::net::Ipv6Addr = "2001:db8:1:2:3:4:5:6".parse().unwrap();
        let s = ip_to_base64(std::net::IpAddr::V6(ip));
        assert_eq!(s.len(), 24); // 8 segs × 3 chars each
        assert!(!s.contains('_'));
    }

    #[test]
    fn capacity_parsing() {
        // Server AB with capacity mask AAC (= 2)
        let (sn, mask) = parse_server_numeric_capacity("ABAAC").unwrap();
        assert_eq!(sn.0, 1);
        assert_eq!(mask, 2);
    }

    #[test]
    fn capacity_to_base64_always_three_chars() {
        // nefarious2/ircd/numnicks.c:SetServerYXX only accepts the
        // 5-char YYXXX form as "2 char numeric + 3 char capacity";
        // any other total length falls back to 1+2. Our encoding
        // must therefore always be 3 chars regardless of value.
        for caps in [1u32, 16, 64, 1024, 4096, 65536, 262144] {
            let s = capacity_to_base64(caps);
            assert_eq!(s.len(), 3, "capacity {caps} produced {s:?}");
        }
    }
}
