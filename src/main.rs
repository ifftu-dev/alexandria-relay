//! Binary entry point for the Alexandria relay. See the library crate docs.

use alexandria_relay::config::{generate_seed, keypair_from_seed, Command};
use alexandria_relay::{doctor, start, Cli, RelayConfig};
use clap::Parser;
use zeroize::Zeroizing;

fn main() {
    let cli = Cli::parse();
    let command = cli.command;

    // The doctor's summary is the output; relay logs stay at warn unless
    // RUST_LOG asks for more.
    let default_log = if command == Some(Command::Doctor) {
        "warn"
    } else {
        "info"
    };
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_log)).init();

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
        println!("To list this relay in a network, add its PeerId to the network");
        println!("profile in the app repository (src-tauri/resources/networks/):");
        println!("  - an entry in `relays`, for clients to connect through it;");
        println!("  - `receipt_issuer_keys`, only if its username receipts are to be trusted.");
        println!("A relay can join the mesh without either: see docs/self-hosting.md.");
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

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    match command {
        Some(Command::Doctor) => {
            let report = runtime.block_on(doctor::run(config));
            print!("{report}");
            std::process::exit(if report.passed() { 0 } else { 1 });
        }
        None => runtime.block_on(run(config)),
    }
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
