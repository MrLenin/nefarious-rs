use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use openssl::nid::Nid;
use tokio::net::TcpListener;
use tracing::{error, info};

use irc_config::Config;

use crate::connection::handle_connection;
use crate::state::ServerState;

/// Start the IRC server with the given configuration.
pub async fn run(
    config: Config,
    config_path: Option<PathBuf>,
    ssl_cert: Option<&Path>,
    ssl_key: Option<&Path>,
    sasl_accounts: Option<String>,
) {
    let mut state_inner = ServerState::new(config.clone());
    if let Some(spec) = sasl_accounts {
        state_inner.account_store = build_account_store_from_env(&spec).await;
    }
    // Record the path so /REHASH has something to reparse. A None
    // here means the server was started without a file — /REHASH
    // will refuse cleanly rather than silently succeeding on an
    // empty config.
    if let Some(p) = config_path {
        *state_inner
            .config_path
            .write()
            .expect("config_path lock poisoned") = Some(p);
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

    // GeoIP: open the MMDB if MMDB_FILE is configured. Failure is
    // logged and GeoIP stays disabled; the server runs fine either
    // way, clients just don't get tagged with country codes.
    if let Err(e) = state.reload_geoip() {
        tracing::warn!("GeoIP load failed: {e}");
    } else if state.geoip_reader().is_some() {
        info!("GeoIP MMDB loaded");
    }

    // Set up SSL acceptor if we have cert/key. Store the paths on
    // state so reload_ssl() can rebuild later (gitsync cert
    // install, SIGUSR1-style reload, future admin commands).
    // Prefer config-driven paths over the CLI/env-driven ones
    // since they can be changed via /REHASH without restart.
    let cfg = state.config.load();
    let cert_path = cfg
        .ssl_certfile()
        .map(std::path::PathBuf::from)
        .or_else(|| ssl_cert.map(std::path::PathBuf::from));
    let key_path = cfg
        .ssl_keyfile()
        .map(std::path::PathBuf::from)
        .or_else(|| ssl_key.map(std::path::PathBuf::from));
    drop(cfg);

    if let (Some(cert), Some(key)) = (cert_path.clone(), key_path.clone()) {
        match crate::ssl::build_acceptor(&cert, &key) {
            Ok(a) => {
                info!("TLS enabled with cert={} key={}", cert.display(), key.display());
                state.ssl_acceptor.store(Arc::new(Some(a)));
                *state.ssl_paths.write().expect("ssl_paths lock") =
                    Some(crate::state::SslPaths { cert, key });
            }
            Err(e) => {
                error!("failed to set up TLS: {e}");
            }
        }
    } else {
        info!("no TLS certificate configured — SSL ports will be skipped");
    }

    // Bind listeners for all ports (client and server)
    let mut handles = Vec::new();

    for port_config in &config.ports {
        if port_config.ssl && state.ssl_acceptor_snapshot().is_none() {
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

        let state_clone = Arc::clone(&state);
        let is_ssl = port_config.ssl;
        let is_server = port_config.server;
        let port = port_config.port;

        let handle = tokio::spawn(async move {
            accept_loop(listener, state_clone, is_ssl, is_server, port).await;
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

    // DNSBL cache sweeper: drop expired per-IP results every 5
    // minutes so a long-running server doesn't accumulate stale
    // entries forever. Cheap no-op when no DNSBL blocks are
    // configured (the cache simply never gets populated).
    crate::dnsbl::spawn_cache_sweeper(
        Arc::clone(&state.dnsbl_cache),
        Arc::clone(&state.shutdown),
    );

    // Git config sync: if GIT_CONFIG_PATH is set, spawn a
    // background loop that runs `git pull --ff-only` on the
    // configured interval and, when HEAD moves, triggers a
    // reload_config(). /GITSYNC lets opers force a pull between
    // scheduled runs.
    if state.config.load().git_config_path().is_some() {
        let sync_state = Arc::clone(&state);
        tokio::spawn(async move {
            crate::gitsync::run_loop(sync_state).await;
        });
        info!("git config sync enabled");
    }

    // Autoconnect: every Connect block with `autoconnect = yes`
    // gets a background task that tries to open the link once at
    // startup and retries on a back-off if the attempt fails. The
    // retry cadence is intentionally simple (fixed 60s) — more
    // sophisticated back-off / jitter can layer on if we start
    // seeing flapping links. Uses the same outbound handshake as
    // the oper-invoked /CONNECT.
    for connect in &config.connects {
        if !connect.autoconnect {
            continue;
        }
        let state = Arc::clone(&state);
        let name = connect.name.clone();
        let shutdown = Arc::clone(&state.shutdown);
        tokio::spawn(async move {
            loop {
                if state.links.iter().any(|e| e.value().name == name) {
                    // Already linked — nothing to do. Sleep then
                    // re-check; if the link drops we'll retry.
                    let sleep = tokio::time::sleep(std::time::Duration::from_secs(60));
                    tokio::pin!(sleep);
                    tokio::select! {
                        biased;
                        _ = shutdown.notified() => return,
                        _ = &mut sleep => {}
                    }
                    continue;
                }
                info!("autoconnect: attempting link to {name}");
                match initiate_server_connection(
                    Arc::clone(&state),
                    name.clone(),
                    None,
                )
                .await
                {
                    Ok(()) => info!("autoconnect: {name} established"),
                    Err(e) => tracing::warn!("autoconnect {name}: {e}"),
                }
                // Whether success or failure, wait before the next
                // attempt. Success means the link is up now; loop
                // top sees it and sleeps without reconnecting.
                let sleep = tokio::time::sleep(std::time::Duration::from_secs(60));
                tokio::pin!(sleep);
                tokio::select! {
                    biased;
                    _ = shutdown.notified() => return,
                    _ = &mut sleep => {}
                }
            }
        });
    }

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
            // Pick up whichever acceptor is live at accept time.
            // Hot reloads via state.reload_ssl() take effect on the
            // next connection; in-flight handshakes keep the
            // acceptor they started with.
            let acceptor_snapshot = state.ssl_acceptor_snapshot();
            if acceptor_snapshot.is_some() {
                let is_server = is_server;
                tokio::spawn(async move {
                    let acceptor_ref = acceptor_snapshot
                        .as_ref()
                        .as_ref()
                        .expect("checked non-None");
                    let ssl = match openssl::ssl::Ssl::new(acceptor_ref.context()) {
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

/// Initiate an outbound S2S connection to a configured Connect
/// block. Opens the TCP socket, sends our PASS + SERVER intro
/// first (reverse of the inbound handshake), reads the remote's
/// PASS + SERVER reply, then hands off to the regular link
/// handler with `suppress_greeting = true` so the greeting isn't
/// repeated.
///
/// Used by the oper-invoked /CONNECT command and (eventually) by
/// an autoconnect task that walks Connect blocks with
/// `autoconnect = yes` at startup.
pub async fn initiate_server_connection(
    state: Arc<ServerState>,
    connect_name: String,
    override_port: Option<u16>,
) -> Result<(), String> {
    use tokio::net::TcpStream;

    let cfg = state.config.load();
    let connect = match cfg.connects.iter().find(|c| c.name == connect_name) {
        Some(c) => c.clone(),
        None => return Err(format!("no Connect block for {connect_name}")),
    };

    let port = override_port.unwrap_or(connect.port);
    let addr = format!("{host}:{port}", host = connect.host);
    info!(
        "initiating outbound link to {connect_name} at {addr} (ssl={})",
        connect.ssl
    );

    let stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| format!("connect({addr}): {e}"))?;

    if connect.ssl {
        let ssl_stream = wrap_outbound_tls(stream, &connect.host).await?;
        do_outbound_handshake(ssl_stream, state, connect).await
    } else {
        do_outbound_handshake(stream, state, connect).await
    }
}

/// Build an outbound TLS stream using a permissive verifier.
///
/// P10 S2S links authenticate via the Connect block's password, not
/// via PKI — hitting a TLS-only peer with a self-signed cert is
/// normal for private networks, and refusing the link when the CA
/// chain doesn't validate would be unhelpful. We still *request*
/// the peer's cert (so future work can add optional pinning) and
/// set SNI to the configured host so virtual-hosted TLS endpoints
/// route correctly.
async fn wrap_outbound_tls<S>(
    stream: S,
    hostname: &str,
) -> Result<tokio_openssl::SslStream<S>, String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

    let mut builder = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("SSL builder: {e}"))?;
    builder.set_verify_callback(SslVerifyMode::PEER, |_preverify_ok, _ctx| true);
    let connector = builder.build();

    let config = connector
        .configure()
        .map_err(|e| format!("SSL configure: {e}"))?;
    // SNI: strip any port, keep the host. If hostname is literally
    // a numeric IP openssl still accepts it via SNI though most
    // peers will ignore the value in that case.
    let sni = hostname.trim_end_matches(':');
    let ssl = config
        .into_ssl(sni)
        .map_err(|e| format!("SSL build: {e}"))?;

    let mut ssl_stream = tokio_openssl::SslStream::new(ssl, stream)
        .map_err(|e| format!("SslStream::new: {e}"))?;
    std::pin::Pin::new(&mut ssl_stream)
        .connect()
        .await
        .map_err(|e| format!("TLS handshake: {e}"))?;
    Ok(ssl_stream)
}

async fn do_outbound_handshake<S>(
    stream: S,
    state: Arc<ServerState>,
    connect: irc_config::ConnectConfig,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use futures::{SinkExt, StreamExt};
    use tokio_util::codec::{Framed, LinesCodec};

    let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(8192));

    // Send our PASS + SERVER lines first. The remote will validate
    // PASS against its matching Connect block (keyed on our name)
    // and respond with its own pair. Any mismatch closes the
    // socket cleanly from the other end.
    let our_numeric = state.numeric;
    let our_capacity = format!(
        "{}{}",
        our_numeric,
        p10_proto::numeric::capacity_to_base64(4096)
    );
    let our_start_ts = state.start_timestamp;
    let link_ts_now = chrono::Utc::now().timestamp() as u64;
    let pass_line = format!("PASS :{}", connect.password);
    let server_line = format!(
        "SERVER {} 1 {} {} J10 {} +6 :{}",
        state.server_name,
        our_start_ts,
        link_ts_now,
        our_capacity,
        state.server_description
    );
    framed
        .send(pass_line)
        .await
        .map_err(|e| format!("send PASS: {e}"))?;
    framed
        .send(server_line)
        .await
        .map_err(|e| format!("send SERVER: {e}"))?;

    // Read their PASS + SERVER.
    let mut their_pass = String::new();
    let mut their_server_params: Vec<String> = Vec::new();
    while let Some(result) = framed.next().await {
        let line = result.map_err(|e| format!("read: {e}"))?;
        tracing::debug!("outbound recv: {line}");
        if line.starts_with("PASS ") {
            their_pass = line
                .strip_prefix("PASS ")
                .unwrap_or("")
                .strip_prefix(':')
                .unwrap_or(&line[5..])
                .to_string();
        } else if line.starts_with("SERVER ") {
            if let Some(msg) = irc_proto::Message::parse(&line) {
                their_server_params = msg.params;
            }
            break;
        } else if line.starts_with("ERROR") {
            return Err(format!("remote rejected link: {line}"));
        }
    }
    if their_server_params.is_empty() {
        return Err("outbound: no SERVER message received".into());
    }

    let stream = framed.into_inner();
    crate::s2s::link::handle_server_link_outbound(
        stream,
        state,
        their_pass,
        their_server_params,
    )
    .await;
    Ok(())
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

// SSL acceptor construction lives in crate::ssl so state.rs can
// call it from reload_ssl(). Server startup uses the same helper.
