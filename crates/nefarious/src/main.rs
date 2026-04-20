mod channel;
mod client;
mod connection;
mod dns;
mod handlers;
mod numeric;
mod s2s;
mod server;
mod state;

use std::path::PathBuf;

use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();

    let config_path = args
        .get(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("ircd.conf"));

    let ssl_cert = std::env::var("SSL_CERT")
        .ok()
        .map(PathBuf::from);
    let ssl_key = std::env::var("SSL_KEY")
        .ok()
        .map(PathBuf::from);

    info!("nefarious-rs v{}", env!("CARGO_PKG_VERSION"));
    info!("loading config from {}", config_path.display());

    let config = match irc_config::Config::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("failed to load config: {e}");
            std::process::exit(1);
        }
    };

    info!(
        "server name: {}, numeric: {}",
        config.general.name, config.general.numeric
    );
    info!(
        "ports: {:?}",
        config.ports.iter().map(|p| p.port).collect::<Vec<_>>()
    );

    // Run the async server
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime");

    rt.block_on(server::run(
        config,
        ssl_cert.as_deref(),
        ssl_key.as_deref(),
    ));
}
