# CI deploy chain, Fly configs, staging

Triage: ready-for-agent
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md
Blocked by: alexandria-relay/docs/relay-transports/02-proxy-protocol-v2.md, alexandria-relay/docs/relay-transports/04-probe-subcommand.md

## Task

Spec sections "CI deploy", "Fly configs" and the Config/Isolation/Workflow
parts of "Staging rehearsal". User stories 34–40, 43–45, 49.

1. Deploy job becomes Frankfurt → probe → Singapore → probe; probe steps run
   the published image by digest with no secrets and the profile fetched
   from the app repository.
2. Manual trigger `target` choice (`staging` default, `production`, `none`);
   `staging` job with `staging_quic` input and the pinned-PeerId probe.
3. `fly.toml`, `fly-eu.toml` changes; new `fly-staging.toml`.
4. The workflow cannot run here; validate YAML syntax (actionlint if
   available) and keep existing jobs' behaviour for tags unchanged.
