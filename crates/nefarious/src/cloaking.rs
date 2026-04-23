//! IP and hostname cloaking.
//!
//! Ports nefarious2 ircd_cloaking.c so cloaked hosts on a mixed
//! Rust/C network match byte-for-byte. Same keys + same algorithm
//! produce the same output, which matters because bans and
//! account-bind decisions are made against the cloaked form.
//!
//! Output shapes:
//!   IPv4 → `ALPHA.BETA.GAMMA.DELTA.IP` (4 x 24-bit hex)
//!   IPv6 → `ALPHA:BETA:GAMMA:IP` (3 x 24-bit hex)
//!   Resolved host → `<PREFIX>-<ALPHA>.<remainder>`
//!
//! The three `KEY1/2/3` and `PREFIX` values come from the
//! `HOST_HIDING_KEY1` / `..._KEY2` / `..._KEY3` / `..._PREFIX`
//! features. Operators must configure matching keys across every
//! server on the network — mismatched keys desync cloaked hosts.

use md5::{Digest, Md5};

/// MD5-digest a byte slice and return the 16-byte hash.
fn md5(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// 128-bit → 24-bit XOR fold, matching nefarious2's downsample24.
/// Three bytes out packed into a u32 (top byte zero), used by the
/// IP cloaking paths where each segment is emitted as `%X`.
fn downsample24(hash: &[u8; 16]) -> u32 {
    let r0 = hash[0] ^ hash[1] ^ hash[2] ^ hash[3] ^ hash[4];
    let r1 = hash[5] ^ hash[6] ^ hash[7] ^ hash[8] ^ hash[9] ^ hash[10];
    let r2 = hash[11] ^ hash[12] ^ hash[13] ^ hash[14] ^ hash[15];
    ((r0 as u32) << 16) | ((r1 as u32) << 8) | (r2 as u32)
}

/// 128-bit → 32-bit XOR fold, matching nefarious2's downsample.
/// Used by the resolved-host path (`normalhost`) where the alpha
/// is printed as a single 32-bit hex chunk.
fn downsample32(hash: &[u8; 16]) -> u32 {
    let r0 = hash[0] ^ hash[1] ^ hash[2] ^ hash[3];
    let r1 = hash[4] ^ hash[5] ^ hash[6] ^ hash[7];
    let r2 = hash[8] ^ hash[9] ^ hash[10] ^ hash[11];
    let r3 = hash[12] ^ hash[13] ^ hash[14] ^ hash[15];
    ((r0 as u32) << 24) | ((r1 as u32) << 16) | ((r2 as u32) << 8) | (r3 as u32)
}

/// One "round" of the cloak: md5 of the salted input, then md5 of
/// that with a trailing key, then fold to 24 bits. Replicates the
/// C idiom:
///   first = md5(buf);
///   strcpy(first + 16, key_suffix);    // clobbers past end
///   second = md5(first[..16 + strlen(key_suffix)]);
///   alpha = downsample24(second);
fn cloak_round(input: &str, trailing_key: &str) -> u32 {
    // Inner hash over the salted input (KEY:addr:KEY).
    let first = md5(input.as_bytes());
    // Outer hash: first 16 bytes are the inner digest, then
    // concatenate the trailing key bytes. C uses strcpy which
    // writes into the buffer at offset 16 — we build a Vec of
    // the same shape.
    let mut outer = Vec::with_capacity(16 + trailing_key.len());
    outer.extend_from_slice(&first);
    outer.extend_from_slice(trailing_key.as_bytes());
    let second = md5(&outer);
    downsample24(&second)
}

/// Cloak an IPv4 address. Output form: `ALPHA.BETA.GAMMA.DELTA.IP`.
/// `keys` is `[KEY1, KEY2, KEY3]` in the config's declared order.
/// All three are treated as byte strings so non-ASCII chars in the
/// keys behave identically to the C implementation.
pub fn hidehost_ipv4(octets: [u8; 4], keys: [&str; 3]) -> String {
    let [a, b, c, d] = octets;
    let (k1, k2, k3) = (keys[0], keys[1], keys[2]);
    let alpha = cloak_round(&format!("{k2}:{a}.{b}.{c}.{d}:{k3}"), k1);
    let beta = cloak_round(&format!("{k3}:{a}.{b}.{c}:{k1}"), k2);
    let gamma = cloak_round(&format!("{k1}:{a}.{b}:{k2}"), k3);
    let delta = cloak_round(&format!("{k2}:{a}:{k1}:{k3}"), k1);
    format!("{alpha:X}.{beta:X}.{gamma:X}.{delta:X}.IP")
}

/// Cloak an IPv6 address. Output form: `ALPHA:BETA:GAMMA:IP`.
/// Expects the 8 halfwords in host order (matches nefarious2's
/// `ntohs(ip->in6_16[i])`).
pub fn hidehost_ipv6(halfwords: [u16; 8], keys: [&str; 3]) -> String {
    let [a, b, c, d, e, f, g, h] = halfwords;
    let (k1, k2, k3) = (keys[0], keys[1], keys[2]);
    let alpha = cloak_round(
        &format!("{k2}:{a:x}:{b:x}:{c:x}:{d:x}:{e:x}:{f:x}:{g:x}:{h:x}:{k3}"),
        k1,
    );
    let beta = cloak_round(
        &format!("{k3}:{a:x}:{b:x}:{c:x}:{d:x}:{e:x}:{f:x}:{g:x}:{k1}"),
        k2,
    );
    let gamma = cloak_round(
        &format!("{k1}:{a:x}:{b:x}:{c:x}:{d:x}:{k2}"),
        k3,
    );
    // C emits 3 segments then `IP` for v6 but computes 4. We
    // keep the compute symmetric to the C version for key
    // churn insensitivity, but the print drops delta — matches
    // the `%X:%X:%X:IP` format string in ircd_cloaking.c:204.
    let _delta = cloak_round(&format!("{k2}:{a:x}:{b:x}:{k1}:{k3}"), k1);
    format!("{alpha:X}:{beta:X}:{gamma:X}:IP")
}

/// Cloak a resolved hostname. Output: `<prefix>-<alpha>.<rem>`
/// where `<rem>` is the suffix after dropping the leading N
/// components (configurable). `components = 1` keeps the TLD;
/// `components = 2` keeps the TLD + second-level; etc.
pub fn hidehost_normalhost(host: &str, components: usize, keys: [&str; 3], prefix: &str) -> String {
    let (k1, k2, k3) = (keys[0], keys[1], keys[2]);

    let inner = md5(format!("{k1}:{host}:{k2}").as_bytes());
    let mut outer = Vec::with_capacity(16 + k3.len());
    outer.extend_from_slice(&inner);
    outer.extend_from_slice(k3.as_bytes());
    let alpha = downsample32(&md5(&outer));

    // Walk the host picking off components until we've skipped
    // `components` dots. What remains becomes the visible tail.
    let dots_to_skip = components;
    let mut seen_dots = 0;
    let mut split_at: Option<usize> = None;
    for (i, ch) in host.char_indices() {
        if ch == '.' {
            seen_dots += 1;
            if seen_dots >= dots_to_skip {
                split_at = Some(i + 1);
                break;
            }
        }
    }

    match split_at {
        Some(i) if i < host.len() => {
            format!("{prefix}-{alpha:X}.{rem}", rem = &host[i..])
        }
        _ => format!("{prefix}-{alpha:X}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downsample24_folds_correctly() {
        // Trivial all-zero hash folds to 0.
        assert_eq!(downsample24(&[0u8; 16]), 0);
        // All-0xff hash: each lane XORs its 5 bytes to 0xff, output
        // packs to 0x00ffffff = 16777215.
        assert_eq!(downsample24(&[0xff; 16]), 0x00ffffff);
    }

    #[test]
    fn downsample32_shape() {
        assert_eq!(downsample32(&[0u8; 16]), 0);
        let mut h = [0u8; 16];
        h[0] = 0x10; // r0 = 0x10
        h[4] = 0x20; // r1 = 0x20
        h[8] = 0x30; // r2 = 0x30
        h[12] = 0x40; // r3 = 0x40
        assert_eq!(downsample32(&h), 0x10203040);
    }

    #[test]
    fn ipv4_cloak_is_deterministic() {
        let keys = ["secret1", "secret2", "secret3"];
        let a = hidehost_ipv4([192, 168, 1, 42], keys);
        let b = hidehost_ipv4([192, 168, 1, 42], keys);
        assert_eq!(a, b);
        assert!(a.ends_with(".IP"));
        // Sanity: different IP → different output. (Not a strong
        // check — the algorithm is surjective — but catches gross
        // bugs like "forgot to salt at all".)
        let c = hidehost_ipv4([192, 168, 1, 43], keys);
        assert_ne!(a, c);
    }

    #[test]
    fn ipv6_cloak_is_deterministic() {
        let keys = ["k1", "k2", "k3"];
        let hw = [0x2001, 0x0db8, 0, 0, 0, 0, 0, 1];
        let a = hidehost_ipv6(hw, keys);
        let b = hidehost_ipv6(hw, keys);
        assert_eq!(a, b);
        assert!(a.ends_with(":IP"));
    }

    #[test]
    fn normalhost_drops_leading_components() {
        let keys = ["k1", "k2", "k3"];
        let out = hidehost_normalhost("host.example.net", 1, keys, "clk");
        // With components=1, after first dot the remainder is
        // "example.net", so form is "clk-<ALPHA>.example.net".
        assert!(out.starts_with("clk-"));
        assert!(out.ends_with(".example.net"));
    }

    #[test]
    fn normalhost_no_dots_just_prefix() {
        let keys = ["k1", "k2", "k3"];
        let out = hidehost_normalhost("singleton", 1, keys, "clk");
        assert!(out.starts_with("clk-"));
        assert!(!out.contains('.'));
    }
}
