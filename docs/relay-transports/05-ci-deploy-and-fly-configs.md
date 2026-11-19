# CI deploy chain, Fly configs, staging

Triage: done
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

## Notes

2026-11-19: Done. The deploy, probe and staging steps live once in a
reusable workflow, `.github/workflows/fly-deploy.yml`, which `ci.yml` calls
as `deploy-frankfurt`, then `deploy-singapore` (needs Frankfurt), and
`staging`. The probe host is `<app>.fly.dev` from the Fly config's `app`
line; production pins the PeerId with the profile fetched from the app
repository's default branch (raw `HEAD` URL), staging with
`vars.STAGING_RELAY_PEER_ID`, checked before anything changes on Fly. The
image is pulled after the registry login and the probe step runs it with
`--pull never` and no secrets in its environment. Choices the spec left open:
`probe --help` runs in its own job on pre-release tags and on manual
`target: none` runs, where nothing deploys; a `staging_quic` run deploys with
`flyctl deploy --env RELAY_QUIC=true` and records how many of five 30 s QUIC
probes passed in the job summary, without failing; staging runs in `fra` on
production's machine size. Validated with actionlint (with shellcheck) and
`flyctl config validate --strict` on all three Fly configs; the profile fetch
and the probe command were run locally against the Frankfurt relay and
passed.
