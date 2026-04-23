//! TLS acceptor construction.
//!
//! Separated from server.rs so `state.rs::reload_ssl()` can
//! rebuild the acceptor in the same shape the initial listener
//! setup uses. Any cert chain / verifier policy change goes here
//! so startup and hot-reload paths stay in sync.

use std::path::Path;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};

/// Build a server-side SSL acceptor from PEM files on disk.
///
/// Requests — but doesn't require — a client certificate so SASL
/// EXTERNAL has something to bind to. The verify callback always
/// returns `true`: we're not pinning a CA chain, the account store
/// is the authority that decides whether the cert CN maps to an
/// account.
pub fn build_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;
    builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
    Ok(builder.build())
}
