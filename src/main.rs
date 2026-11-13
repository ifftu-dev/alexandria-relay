//! Binary entry point for the Alexandria relay. See the library crate docs.

use alexandria_relay::config::{generate_seed, keypair_from_seed};
use alexandria_relay::{start, Cli, RelayConfig};
use clap::Parser;
use zeroize::Zeroizing;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    if cli.generate_key {
        let seed = generate_seed();
        let keypair = keypair_from_seed(&seed);
        let peer_id = keypair.public().to_peer_id();
        println!("Generated relay keypair:");
        println!("  Seed (save this):  {seed}");
        println!("  PeerId:            {peer_id}");
        println!();
        println!("Deploy with:");
        println!("  RELAY_SEED={seed} alexandria-relay --port 4001");
        println!();
        println!("Add to main app's discovery.rs:");
        println!("  const RELAY_PEER_ID: &str = \"{peer_id}\";");
        return;
    }

    let mut config = cli.into_config();

    // Read and clear RELAY_SEED while single-threaded (safe — no tokio runtime yet).
    // The copy we keep is zeroized when it drops; the process environment's
    // own copy is released by `remove_var`, which is the most we can do there.
    let seed = std::env::var("RELAY_SEED").ok().map(Zeroizing::new);
    if seed.is_some() {
        std::env::remove_var("RELAY_SEED");
    }
    config.keypair = seed.as_deref().map(|s| keypair_from_seed(s));
    config.admin_token = std::env::var("RELAY_ADMIN_TOKEN").ok();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(run(config));
}

/// Start the relay, then shut it down gracefully on SIGTERM or SIGINT.
async fn run(config: RelayConfig) {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("SIGTERM handler");

    let handle = match start(config).await {
        Ok(handle) => handle,
        Err(e) => {
            log::error!("Relay failed to start: {e}");
            std::process::exit(1);
        }
    };

    tokio::select! {
        _ = sigterm.recv() => log::info!("Received SIGTERM, shutting down gracefully..."),
        _ = tokio::signal::ctrl_c() => log::info!("Received SIGINT, shutting down gracefully..."),
    }
    handle.shutdown().await;
}
