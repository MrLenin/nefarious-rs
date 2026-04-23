mod accounts;
mod capabilities;
mod channel;
mod client;
mod cloaking;
mod connection;
mod dns;
mod gline;
mod handlers;
mod ipcheck;
mod jupe;
mod numeric;
mod s2s;
mod server;
mod shun;
mod state;
mod tags;
mod zline;

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

    // Quick path for populating the SASL in-memory account store from
    // the environment. Format: `NEFARIOUS_ACCOUNTS=alice:secret,bob:pw`.
    // Real backends (IAuth / Keycloak / config-file) come later in
    // Phase 3; this is the dev shortcut so SASL PLAIN is testable
    // immediately. Any value containing credentials is obviously
    // operator-only — document it as such.
    let sasl_accounts = std::env::var("NEFARIOUS_ACCOUNTS").ok();

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
        Some(config_path),
        ssl_cert.as_deref(),
        ssl_key.as_deref(),
        sasl_accounts,
    ));
}
