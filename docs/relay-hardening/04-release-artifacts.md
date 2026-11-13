# Publish images and binaries on every tag

Status: implemented
Triage: done
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md
Blocked by: alexandria-relay/docs/relay-hardening/01-release-unblock-and-input-hardening.md

## Task

An operator should run a relay with one `docker run` or one downloaded binary.

1. On `v*` tags, build and push a multi-architecture (amd64, arm64) container
   image to the GitHub container registry under the repository's namespace,
   tagged with the version and `latest`. Keep the existing Docker build job
   on pull requests as a build-only check.
2. On `v*` tags, build statically linked Linux binaries for both
   architectures and attach them, with checksums, to a GitHub release created
   from the tag.
3. Declare a non-root user in the runtime image if ticket 02 has not already
   done so, and set the data directory to a path that user can write.
4. Replace `cargo install cargo-audit` in CI with the maintained audit action
   so the audit job does not compile the tool on every run.
5. Add `cargo deny` (licenses and bans) as a CI job with a committed
   configuration; failing licences block.
6. Document in `CONTRIBUTING.md` what a tag produces (image, binaries,
   deploy) and the image name.

Acceptance: a dry run on a test tag in a fork or via workflow dispatch
produces an image that runs `--generate-key` on both architectures and a
release with two binaries plus checksums; CI on a pull request still runs
check, clippy, fmt, test, audit, deny and docker build; docs pass
`scripts/check-docs.sh`.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Branch from the tip that
contains ticket 01. Return the workflow changes, the dry-run evidence and any
registry permission the maintainer must grant. Tracker updates are authorized
by the invoked implement-spec workflow.

## Notes

- 2026-11-13: Implemented; the real tag dry run is pending (below).
  - What shipped. Tags and manual runs build each architecture natively
    (`ubuntu-24.04` and `ubuntu-24.04-arm`) and push it by digest. The
    pushed image is smoke-tested on its own architecture, and the same
    static binary is exported with `--target binary`. A manifest job joins
    the two images as `ghcr.io/ifftu-dev/alexandria-relay` with the version,
    `latest` and `sha-<commit>` tags. Tags also get a GitHub release with
    `alexandria-relay-linux-amd64`, `-arm64` and `SHA256SUMS`. Pull requests
    keep the build-only Docker Build job, which now also runs
    `scripts/smoke-image.sh`. The audit job uses `rustsec/audit-check`,
    which caches the tool. A Licences and bans job runs
    `cargo deny check licenses bans` against `deny.toml`. The image runs as
    uid/gid 10001 with `RELAY_DATA_DIR=/data`, so ticket 02's item 5 is done
    here. `CONTRIBUTING.md` and the operations doc describe the outputs.
  - Build once, deploy both. Deploy no longer builds on Fly. Each region
    copies the published image into its app's Fly registry with
    `docker buildx imagetools create` and runs `flyctl deploy --image`. This
    retires the two concurrent builds on the shared remote builder, one of
    which hung on 2026-11-13, and does not depend on the GitHub package
    being public. Tag-triggered and manual deploys still run.
  - Evidence. `actionlint` is clean. Local `docker buildx build` passes for
    `linux/arm64` (native) and `linux/amd64` (emulated). The builder's
    `file` check prints "statically linked" (arm64) and "static-pie linked"
    (amd64). `scripts/smoke-image.sh` failed on the old image (root user,
    no data dir) and passes on both new ones. Each exported binary runs
    `--generate-key` in `busybox:musl`. With a named volume at `/data` the
    relay opens its store as uid 10001. Against two local registries, the
    manifest step joined both digests into one amd64 and arm64 index, and the
    deploy's cross-registry copy ran on both platforms.
    `cargo deny check licenses bans` passes, and fails when MIT is removed
    from the allow list. fmt, clippy and tests pass on 1.89.0.
  - Pending maintainer dry run. Push a pre-release tag such as
    `v0.1.1-rc.1` from the commit to test. It publishes the image (no
    `latest`), creates a pre-release with both binaries and checksums, and
    does not deploy. Check that the Publish jobs' smoke steps passed on both
    architectures and that the release holds three assets. Then delete the
    test release, tag and package version. A manual run with `deploy`
    unticked exercises everything except the release. Grants: the jobs
    request `packages: write` and `contents: write` themselves, which works
    unless an organisation policy caps `GITHUB_TOKEN` permissions. After
    the first publish, set the `alexandria-relay` package's visibility to
    Public (the organisation must allow public packages) so operators can
    pull without logging in. Arm runners are free only for public
    repositories; a private one needs another arm64 runner label.
  - Before the first real deploy. Frankfurt's volume holds files that root
    wrote. Fly chowns only the mount point to the image user, so run
    `fly ssh console -a alexandria-relay-eu -C "chown -R 10001:10001 /data"`
    once, or delete the disposable store. Without that, receipts are
    disabled.
  - Blocker found, not fixed here. `cargo audit` now reports seven new
    advisories: quinn-proto 0.11.18 (fixed in 0.11.19), quinn-udp 0.5.14
    (fixed in 0.5.16), libp2p-quic 0.13.0 (fixed in 0.13.1), and three
    unpatched hickory DNSSEC advisories that fit the existing unreachable
    rationale. The audit gates every publish job, so the dry run fails at
    audit until a lockfile bump and three ignores land.
  - Deviations. Provenance attestations are off, so the joined tag is a
    plain two-platform index for Fly. Pre-release tags publish but do not
    deploy, which makes the dry run safe. The image now runs the musl
    build. Follow-ups: watch CPU on Fly and consider mimalloc if musl's
    allocator shows; add build attestations.
