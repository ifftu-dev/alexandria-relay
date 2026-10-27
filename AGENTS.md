# alexandria-relay

Single-binary libp2p relay, DHT bootstrap server and username-receipt registry, deployed on Fly.io. Workspace rules (checks, commits, docs) are in the workspace `AGENTS.md`; commit details in `CONTRIBUTING.md`.

- **PeerId is deterministic**: it derives from `RELAY_SEED`. Changing the seed changes the relay's identity, and the app's network profile (`alexandria/src-tauri/resources/networks/preprod.json`) pins it, so a seed change needs a coordinated profile update.
- **Username registry** (`src/username_reg.rs`): countersigned first-seen claims plus a DHT record mirror, persisted under `RELAY_DATA_DIR`. The Fly volume is in Frankfurt; the Mumbai machine is ephemeral.
- **Topic-agnostic**: the relay forwards whatever gossipsub carries. Wire protocol IDs change only in a coordinated app + relay + monitoring deployment.
- **libp2p version** tracks the app's; bump them together.
