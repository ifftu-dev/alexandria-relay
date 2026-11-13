# Unblock releases and bound receipt-request inputs

Status: implemented
Triage: done
Repos: alexandria-relay
Part of: alexandria-relay/docs/relay-hardening-spec.md

## Task

Make the dependency audit pass and close the cheap denial-of-service paths on
the username-receipt protocol. Independent of every other ticket; ship it
first and alone.

1. Bump the SQLite binding to the current major so the SQLite advisory
   clears. This requires Rust 1.89: move the CI toolchain pin, the crate's
   `rust-version` and the Docker build image together. Keep the lockfile
   committed and builds `--locked`.
2. Add ignores for the DNS-library advisories to the audit configuration,
   each with the existing style of justification: the DNS features of libp2p
   are not enabled, the crate is not in the compiled tree (`cargo tree -e
   normal` shows no match), and the condition that would make it reachable
   again.
3. Reject a claim whose DID exceeds a small fixed length before any base58
   decoding. An Ed25519 `did:key` is a fixed-width string; the bound is a
   named constant with a comment stating the width and the quadratic decode
   it protects against.
4. Set the receipt request codec's request-size maximum to a few kilobytes.
5. Add a pending-incoming connection limit to the connection-limits
   behaviour, default in the low hundreds.
6. Zeroize every buffer that held seed material: the decoded byte vector and
   the environment string, not only the fixed array.

Acceptance: `cargo audit` exits zero with only documented ignores; a unit test
shows a DID over the bound is refused with an "invalid claim" reason and a
sub-millisecond path; existing store and limiter tests pass; `cargo fmt
--check`, `cargo clippy --locked -- -D warnings`, `cargo test --locked` and
`docker build .` pass on the new toolchain. Update the operations doc's limits
table for the new caps.

## Implementation workflow

Read the parent spec and the repository `AGENTS.md`. Work on a branch from
`main`; one commit per numbered item where practical, subjects in the
repository's `type(scope): message` form. Return the commits, the audit output
and test evidence. Tracker updates are authorized by the invoked
implement-spec workflow.

## Notes

- 2026-11-13: Done. Merged in PR #14 and deployed to both regions. `cargo
  audit` exits zero with the hickory ignores documented in
  `.cargo/audit.toml`. A 200,000-character DID took 61.7 s to refuse in a
  debug build before the bound and is now refused at once (unit test
  `an_oversized_did_is_refused_before_decoding`). Receipt requests are capped
  at 8 KiB, pending incoming handshakes at 256, and seed buffers are zeroized.
  `docker build .` passed in CI on Rust 1.89.
