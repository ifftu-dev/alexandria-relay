# Publish images and binaries on every tag

Triage: ready-for-agent
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
