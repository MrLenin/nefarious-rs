use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use tokio::net::TcpListener;
use tracing::{error, info};

use irc_config::Config;

use crate::connection::handle_connection;
use crate::state::ServerState;

/// Start the IRC server with the given configuration.
pub async fn run(config: Config, ssl_cert: Option<&Path>, ssl_key: Option<&Path>) {
    let state = Arc::new(ServerState::new(config.clone()));

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

    // Wait for all listeners
    for handle in handles {
        let _ = handle.await;
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
    loop {
        let (stream, addr) = match listener.accept().await {
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
                    if is_server {
                        handle_server_port(ssl_stream, state).await;
                    } else {
                        handle_connection(ssl_stream, addr, state, true, port).await;
                    }
                });
            }
        } else if is_server {
            tokio::spawn(async move {
                handle_server_port(stream, state).await;
            });
        } else {
            tokio::spawn(async move {
                handle_connection(stream, addr, state, false, port).await;
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

fn build_ssl_acceptor(
    cert_path: &Path,
    key_path: &Path,
) -> Result<SslAcceptor, openssl::error::ErrorStack> {
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.check_private_key()?;
    Ok(builder.build())
}
