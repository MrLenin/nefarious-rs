//! Reverse DNS resolution for incoming client connections.
//!
//! Implements the same behaviour as `nefarious2/ircd/ircd_res.c`:
//!
//! 1. PTR lookup of the client's IP.
//! 2. Forward-verify the returned name by looking up its A/AAAA records
//!    and requiring one of them to match the original IP. Without this
//!    step an attacker controlling a PTR record could claim any hostname.
//! 3. On success, replace `Client::host` with the verified name.
//! 4. On timeout, failure, or mismatch, keep the IP as the host.
//!
//! We use `hickory-resolver` for the actual DNS work — the observable
//! behaviour matches `ircd_res.c`, but the implementation is
//! cross-platform async without hand-rolled resolver code.
//!
//! The C server would check `clihost` equality post-resolve; the
//! forward-verify step here is stricter (we accept *any* matching IP in
//! the forward answer, which is correct behaviour for multi-homed hosts).

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_resolver::TokioResolver;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::rr::RData;
use tokio::sync::RwLock;
use tracing::debug;

use irc_proto::{Command, Message};

use crate::client::Client;

const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a shared resolver using the system DNS config (resolv.conf on
/// Unix, registry on Windows). Called once during server start; the
/// handle is cloned per lookup.
pub fn build_resolver() -> Result<TokioResolver, NetError> {
    TokioResolver::builder_tokio()?.build()
}

/// Kick off the reverse lookup in the background. On success, overwrite
/// `client.host` with the verified hostname and send an AUTH notice;
/// on failure, send a "Couldn't look up" notice. Either way the task
/// exits without blocking the connection.
///
/// We skip resolution for loopback and private addresses — those never
/// have useful PTR records and would just slow registration.
pub fn spawn_reverse_lookup(
    resolver: Arc<TokioResolver>,
    server_name: String,
    client: Arc<RwLock<Client>>,
    ip: IpAddr,
) {
    if is_local_or_private(&ip) {
        debug!("skipping reverse DNS for local/private {ip}");
        return;
    }

    // Announce the lookup before we begin, matching the C "AUTH" notice.
    send_auth_notice(&client, &server_name, "*** Looking up your hostname...");

    tokio::spawn(async move {
        let result = tokio::time::timeout(RESOLVE_TIMEOUT, resolve_and_verify(&resolver, ip)).await;

        match result {
            Ok(Ok(name)) => {
                // Only replace the host while the client is still
                // pre-registration. If the user finished NICK+USER
                // already, their prefix is in flight and changing it
                // mid-session would desync other clients.
                let mut c = client.write().await;
                if !c.is_registered() {
                    c.host = name.clone();
                    // Anchor real_host to the resolved name so
                    // /SETHOST undo reverts to what the DNS said,
                    // not to the raw IP.
                    c.real_host = name.clone();
                }
                drop(c);
                send_auth_notice(
                    &client,
                    &server_name,
                    &format!("*** Found your hostname: {name}"),
                );
            }
            Ok(Err(e)) => {
                debug!("reverse DNS for {ip} failed: {e}");
                send_auth_notice(
                    &client,
                    &server_name,
                    "*** Couldn't look up your hostname",
                );
            }
            Err(_) => {
                debug!("reverse DNS for {ip} timed out after {RESOLVE_TIMEOUT:?}");
                send_auth_notice(
                    &client,
                    &server_name,
                    "*** Couldn't look up your hostname (timeout)",
                );
            }
        }
    });
}

fn send_auth_notice(client: &Arc<RwLock<Client>>, server_name: &str, text: &str) {
    // Use try_read so a long-held write lock from registration doesn't
    // stall the DNS task on its final output; if we can't read, drop
    // the notice — it's purely informational.
    if let Ok(c) = client.try_read() {
        c.send(Message::with_source(
            server_name,
            Command::Notice,
            vec!["AUTH".to_string(), text.to_string()],
        ));
    }
}

/// Run PTR → forward-verify. Returns the verified hostname (without
/// trailing dot) on success.
async fn resolve_and_verify(
    resolver: &TokioResolver,
    ip: IpAddr,
) -> Result<String, ResolveFailure> {
    let ptr = resolver
        .reverse_lookup(ip)
        .await
        .map_err(ResolveFailure::Ptr)?;

    for record in ptr.answers() {
        // hickory 0.26 Record has `data` as a public field, not a getter,
        // and Record<R>::data has type R (defaults to RData here).
        let RData::PTR(ptr_name) = &record.data else {
            continue;
        };
        let name_str = ptr_name.0.to_utf8();
        let name_str = name_str.trim_end_matches('.');
        if name_str.is_empty() {
            continue;
        }

        let forward = match resolver.lookup_ip(name_str).await {
            Ok(f) => f,
            Err(e) => {
                debug!("forward lookup of {name_str} failed: {e}");
                continue;
            }
        };

        if forward.iter().any(|a| a == ip) {
            return Ok(name_str.to_string());
        }

        debug!("forward-verify mismatch: {name_str} does not map back to {ip}");
    }

    Err(ResolveFailure::NoVerifiedName)
}

#[derive(Debug, thiserror::Error)]
enum ResolveFailure {
    #[error("PTR lookup failed: {0}")]
    Ptr(#[from] NetError),
    #[error("no PTR answer was forward-verifiable")]
    NoVerifiedName,
}

fn is_local_or_private(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            // std lacks stable is_unique_local / is_unicast_link_local on
            // IpAddr, so inline the prefix checks. fc00::/7 is ULA;
            // fe80::/10 is link-local.
            if v6.is_loopback() || v6.is_unspecified() {
                return true;
            }
            let seg0 = v6.segments()[0];
            (seg0 & 0xfe00) == 0xfc00 || (seg0 & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_loopback_v4() {
        assert!(is_local_or_private(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn skips_rfc1918() {
        assert!(is_local_or_private(&"10.0.0.1".parse().unwrap()));
        assert!(is_local_or_private(&"192.168.1.1".parse().unwrap()));
        assert!(is_local_or_private(&"172.20.0.1".parse().unwrap()));
    }

    #[test]
    fn does_not_skip_public_v4() {
        assert!(!is_local_or_private(&"8.8.8.8".parse().unwrap()));
        assert!(!is_local_or_private(&"1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn skips_v6_loopback_and_ula() {
        assert!(is_local_or_private(&"::1".parse().unwrap()));
        assert!(is_local_or_private(&"fc00::1".parse().unwrap()));
        assert!(is_local_or_private(&"fd00::1".parse().unwrap()));
        assert!(is_local_or_private(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn does_not_skip_public_v6() {
        assert!(!is_local_or_private(&"2001:db8::1".parse().unwrap()));
        assert!(!is_local_or_private(&"2606:4700:4700::1111".parse().unwrap()));
    }
}
