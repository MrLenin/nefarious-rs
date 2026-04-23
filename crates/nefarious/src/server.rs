use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use openssl::nid::Nid;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use tokio::net::TcpListener;
use tracing::{error, info};

use irc_config::Config;

use crate::connection::handle_connection;
use crate::state::ServerState;

/// Start the IRC server with the given configuration.
pub async fn run(
    config: Config,
    ssl_cert: Option<&Path>,
    ssl_key: Option<&Path>,
    sasl_accounts: Option<String>,
) {
    let mut state_inner = ServerState::new(config.clone());
    if let Some(spec) = sasl_accounts {
        state_inner.account_store = build_account_store_from_env(&spec).await;
    }
    // Seed the HLC and msgid-generator YY prefix. Every SourceInfo
    // will route through this for time + msgid. Must happen before
    // any client-event SourceInfo is built.
    crate::tags::init_hlc(state_inner.numeric);
    let state = Arc::new(state_inner);

    // Load MOTD from disk if MPATH is configured. Failure is a
    // warning, not fatal — the built-in banner keeps the server
    // greetable while the operator fixes the path.
    match state.reload_motd() {
        Ok(n) if n > 0 => info!("loaded MOTD ({n} lines)"),
        Ok(_) => {}
        Err(e) => tracing::warn!("MOTD load failed: {e}"),
    }

    // Set up SSL acceptor if we have cert/key
    let ssl_acceptor = match (ssl_cert, ssl_key) {
        (Some(cert), Some(key)) => match build_ssl_acceptor(cert, key) {
            Ok(a) => {
                info!(
                    "TLS enabled with cert={} key={}",
                    cert.display(),
                    key.display()
                );
                Some(Arc::new(a))
            }
            Err(e) => {
                error!("failed to set up TLS: {e}");
                None
            }
        },
        _ => {
            info!("no TLS certificate configured — SSL ports will be skipped");
            None
        }
    };

    // Bind listeners for all ports (client and server)
    let mut handles = Vec::new();

    for port_config in &config.ports {
        if port_config.ssl && ssl_acceptor.is_none() {
            info!("skipping SSL port {} (no certificate)", port_config.port);
            continue;
        }

        let addr = SocketAddr::from(([0, 0, 0, 0], port_config.port));
        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("failed to bind port {}: {e}", port_config.port);
                continue;
            }
        };

        info!(
            "listening on port {} (ssl={}, websocket={:?})",
            port_config.port, port_config.ssl, port_config.websocket
        );

        let state = Arc::clone(&state);
        let ssl = ssl_acceptor.clone();
        let is_ssl = port_config.ssl;
        let is_server = port_config.server;
        let port = port_config.port;

        let handle = tokio::spawn(async move {
            accept_loop(listener, state, ssl, is_ssl, is_server, port).await;
        });
        handles.push(handle);
    }

    if handles.is_empty() {
        error!("no listeners started — check your configuration");
        return;
    }

    // Background sweeper: purge expired GLINE/SHUN/ZLINE/JUPE
    // entries once a minute. Match-time already treats expired
    // entries as non-enforceable so correctness doesn't depend on
    // the sweep, but without it a long-running server accumulates
    // permanently-dead rows in the ban stores.
    let sweep_state = Arc::clone(&state);
    let sweep_shutdown = Arc::clone(&state.shutdown);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = sweep_shutdown.notified() => return,
                _ = ticker.tick() => {}
            }
            let (g, s, z, j) = sweep_state.sweep_expired_bans().await;
            if g + s + z + j > 0 {
                info!(
                    "ban sweep: dropped {g} glines, {s} shuns, {z} zlines, {j} jupes"
                );
            }
        }
    });

    // Signal handler: flip state.shutdown on SIGINT (Ctrl-C) and —
    // on Unix — SIGTERM. Listener loops select on the Notify and
    // exit accept(), which lets the outer handle joins resolve and
    // returns control to the orchestrator. Existing client and
    // server sessions keep running until they close naturally or
    // the orchestrator kills the process. A more thorough drain
    // (broadcast SQUIT, disconnect clients) can layer on later.
    let shutdown = Arc::clone(&state.shutdown);
    tokio::spawn(async move {
        let ctrl_c = tokio::signal::ctrl_c();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("couldn't install SIGTERM handler: {e}");
                    let _ = ctrl_c.await;
                    info!("SIGINT received — starting shutdown");
                    shutdown.notify_waiters();
                    return;
                }
            };
            tokio::select! {
                _ = ctrl_c => info!("SIGINT received — starting shutdown"),
                _ = term.recv() => info!("SIGTERM received — starting shutdown"),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = ctrl_c.await;
            info!("SIGINT received — starting shutdown");
        }
        shutdown.notify_waiters();
    });

    // Wait for all listeners to close (signal handler above flips
    // state.shutdown, accept_loop exits on next iteration).
    for handle in handles {
        let _ = handle.await;
    }
    info!("all listeners closed — starting active drain");

    // Active drain. Broadcast ERROR to every local client so they
    // see a clean reason instead of an abrupt RST, and send SQUIT
    // to each S2S peer so the rest of the network learns we're
    // going away rather than timing us out on PING. We don't wait
    // for the writer tasks to fully flush — a small grace sleep
    // gives them a chance while honouring the operator's 'stop'
    // intent, and anything still in flight dies with the process.
    shutdown_drain(&state).await;
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    info!("drain complete — exiting");
}

/// Notify every local session that we're going down. Best-effort —
/// sends are non-blocking and any that don't fit the client's
/// outbound queue are dropped. Intended to run once, from `run()`
/// after listeners close.
async fn shutdown_drain(state: &Arc<ServerState>) {
    let reason = "Server shutting down";

    // ERROR per client — they render it as "*** ERROR: <reason>".
    // We also tag with QUIT so channel-mates on other servers see
    // the expected departure sequence once S2S routing forwards it.
    for entry in state.clients.iter() {
        let c = entry.value().read().await;
        c.send_raw(irc_proto::Message::with_source(
            &state.server_name,
            irc_proto::Command::Error,
            vec![format!("Closing Link: {} [{reason}]", c.nick)],
        ));
        // Drive a QUIT broadcast through the existing disconnect
        // signal so handle_connection's teardown path fires QUIT
        // fan-out and releases state cleanly.
        c.request_disconnect(reason);
    }

    // SQUIT to each peer. Wire: `<our_numeric> SQ <our_name> 0 :<reason>`.
    // Mirrors m_squit.c's self-originated form used on /RESTART or
    // fatal error in C nefarious2.
    let our_numeric = state.numeric.to_string();
    let line = format!(
        "{our_numeric} SQ {name} 0 :{reason}",
        name = state.server_name
    );
    for entry in state.links.iter() {
        entry.value().send_line(line.clone()).await;
    }
}

/// Accept loop for a single listener.
async fn accept_loop(
    listener: TcpListener,
    state: Arc<ServerState>,
    ssl_acceptor: Option<Arc<SslAcceptor>>,
    is_ssl: bool,
    is_server: bool,
    port: u16,
) {
    let shutdown = Arc::clone(&state.shutdown);
    loop {
        let accept = tokio::select! {
            biased;
            _ = shutdown.notified() => {
                info!("stopping listener on port {port}");
                return;
            }
            a = listener.accept() => a,
        };
        let (stream, addr) = match accept {
            Ok(s) => s,
            Err(e) => {
                error!("accept error on port {port}: {e}");
                continue;
            }
        };

        let state = Arc::clone(&state);

        if is_ssl {
            if let Some(ref acceptor) = ssl_acceptor {
                let acceptor = Arc::clone(acceptor);
                let is_server = is_server;
                tokio::spawn(async move {
                    let ssl = match openssl::ssl::Ssl::new(acceptor.context()) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("SSL context error on port {port}: {e}");
                            return;
                        }
                    };
                    let mut ssl_stream = match tokio_openssl::SslStream::new(ssl, stream) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::debug!("SSL stream creation failed on port {port}: {e}");
                            return;
                        }
                    };
                    if let Err(e) = std::pin::Pin::new(&mut ssl_stream).accept().await {
                        tracing::debug!("TLS handshake failed on port {port}: {e}");
                        return;
                    }
                    // Pull the client cert's CN, if any, for SASL
                    // EXTERNAL. The acceptor is configured with
                    // SSL_VERIFY_PEER + a permissive callback, so the
                    // cert is surfaced but not validated against any
                    // CA; the account store is the authority.
                    let peer_cn = ssl_stream
                        .ssl()
                        .peer_certificate()
                        .and_then(|cert| {
                            cert.subject_name()
                                .entries_by_nid(Nid::COMMONNAME)
                                .next()
                                .and_then(|e| e.data().as_utf8().ok())
                                .map(|s| s.to_string())
                        });
                    if is_server {
                        handle_server_port(ssl_stream, state).await;
                    } else {
                        handle_connection(ssl_stream, addr, state, true, port, peer_cn)
                            .await;
                    }
                });
            }
        } else if is_server {
            tokio::spawn(async move {
                handle_server_port(stream, state).await;
            });
        } else {
            tokio::spawn(async move {
                handle_connection(stream, addr, state, false, port, None).await;
            });
        }
    }
}

/// Handle an inbound connection on a server port.
/// Reads PASS + SERVER, then hands off to the S2S link handler.
async fn handle_server_port<S>(stream: S, state: Arc<ServerState>)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use futures::StreamExt;
    use tokio_util::codec::{Framed, LinesCodec};

    let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(8192));

    let mut password = String::new();
    let mut server_params = Vec::new();

    // Read PASS and SERVER lines
    while let Some(result) = framed.next().await {
        let line = match result {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("server port read error: {e}");
                return;
            }
        };

        tracing::debug!("server port recv: {line}");

        if line.starts_with("PASS ") {
            password = line
                .strip_prefix("PASS ")
                .unwrap_or("")
                .strip_prefix(':')
                .unwrap_or(&line[5..])
                .to_string();
        } else if line.starts_with("SERVER ") {
            let msg = irc_proto::Message::parse(&line);
            if let Some(msg) = msg {
                server_params = msg.params;
            }
            break;
        }
    }

    if server_params.is_empty() {
        tracing::error!("server port: no SERVER message received");
        return;
    }

    // Extract the raw stream and hand off to S2S handler
    let stream = framed.into_inner();
    crate::s2s::link::handle_server_link(stream, state, password, server_params).await;
}

/// Parse a `NEFARIOUS_ACCOUNTS=alice:secret,bob:pw` spec into an
/// in-memory account store. Malformed pairs are logged and skipped
/// so a typo can't break startup.
async fn build_account_store_from_env(spec: &str) -> crate::accounts::SharedAccountStore {
    let mut store = crate::accounts::InMemoryAccountStore::new();
    for entry in spec.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.split_once(':') {
            Some((user, pw)) if !user.is_empty() && !pw.is_empty() => {
                store = store.with_account(user, pw).await;
                info!("SASL account registered: {user}");
            }
            _ => {
                error!("ignoring malformed NEFARIOUS_ACCOUNTS entry: {entry}");
            }
        }
    }
    std::sync::Arc::new(store)
}

fn build_ssl_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;
    // Request — but do not require — the peer's client certificate so
    // SASL EXTERNAL has something to bind to. The verify callback
    // always returns true: we're not pinning a CA chain, the account
    // store is the authority that decides whether the cert CN maps
    // to an account.
    builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
    Ok(builder.build())
}
