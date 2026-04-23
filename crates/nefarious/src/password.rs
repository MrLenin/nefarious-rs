//! Shared password verification for Oper / WebIRC / (future)
//! Client-block passwords.
//!
//! Storage forms:
//! - `$2a$...` / `$2b$...` / `$2y$...` — bcrypt hash, verified via
//!   the `bcrypt` crate.
//! - Everything else — plaintext byte compare.
//!
//! Byte-wise equality is fine for the plaintext path; timing leaks
//! on password length aren't in our threat model (operators and
//! trusted gateways are authenticated principals provisioned out-of-
//! band). Once we move to fully hashed storage the plaintext
//! fallback can be removed.

const BCRYPT_PREFIXES: &[&str] = &["$2a$", "$2b$", "$2y$"];

/// Compare a presented password against its stored form. Detects
/// bcrypt automatically; falls back to plaintext compare.
pub fn verify(presented: &str, stored: &str) -> bool {
    if BCRYPT_PREFIXES.iter().any(|p| stored.starts_with(p)) {
        bcrypt::verify(presented, stored).unwrap_or(false)
    } else {
        presented.as_bytes() == stored.as_bytes()
    }
}
