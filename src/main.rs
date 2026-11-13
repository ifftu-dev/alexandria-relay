//! Binary entry point for the Alexandria relay. See the library crate docs.

use alexandria_relay::config::{generate_seed, keypair_from_seed, Args};
use clap::Parser;
use zeroize::Zeroizing;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    if args.generate_key {
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

    // Read and clear RELAY_SEED while single-threaded (safe — no tokio runtime yet).
    // The copy we keep is zeroized when it drops; the process environment's
    // own copy is released by `remove_var`, which is the most we can do there.
    let seed = std::env::var("RELAY_SEED").ok().map(Zeroizing::new);
    if seed.is_some() {
        std::env::remove_var("RELAY_SEED");
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(alexandria_relay::run(args, seed));
}
