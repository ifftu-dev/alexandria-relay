# Docs and version bump

Triage: done
Updated: 2026-11-19
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-transports-spec.md
Blocked by: alexandria-relay/docs/relay-transports/01-transport-assembly-and-quic-switch.md, alexandria-relay/docs/relay-transports/02-proxy-protocol-v2.md, alexandria-relay/docs/relay-transports/03-quic-protections.md, alexandria-relay/docs/relay-transports/04-probe-subcommand.md, alexandria-relay/docs/relay-transports/05-ci-deploy-and-fly-configs.md

## Task

Spec section "Docs" (including the staging-rehearsal section for
operations.md). User stories 41–42.

1. `operations.md`, `self-hosting.md`, `README.md` settings table, any doc
   comments the earlier tickets left stale. Placeholders only.
2. `Cargo.toml` version 0.4.0 as its own `chore:` commit.

## Notes

2026-11-19: Done. `operations.md` gains the PROXY v2 and QUIC settings
in the limits table, the new `/metrics` fields and Prometheus names, the
`proxy_header_refusal_majority` and `quic_pending_denied_sustained` alerts,
a rewritten client-addresses section (PROXY v2 on the libp2p listener, its
trust model and refusal counters), the QUIC-on-Fly experiment result, the
ports table without 4001/udp, a Rollback section (previous image with the
previous tag's Fly config, region by region, probe after each) and a
Staging rehearsal section (create the app with dedicated IPv4 and IPv6, its
own secrets, `STAGING_RELAY_PEER_ID`, a `FLY_API_TOKEN` that reaches it,
the checklist, teardown). `self-hosting.md` covers when to set
`RELAY_TCP_PROXY_PROTOCOL=v2` and `RELAY_QUIC=false` and gains a `probe`
section (`--health-url` plain `http://` only). Also caught up beyond the
ticket: README's libp2p version, flag table and module list;
CONTRIBUTING's deploy description (chain, `target`, probe); the hardening
list in `src/lib.rs`. `AGENTS.md` describes no transports or ports, so it
is unchanged. `Cargo.toml` was still at 0.1.0 (so `/health` reported
0.1.0 on the 0.3.x and 0.4.0-rc.1 releases); now 0.4.0. The staging job
deploys the image its own run builds, so the rehearsal runs the workflow on
the release candidate's tag, which also re-uploads that release's binaries.
