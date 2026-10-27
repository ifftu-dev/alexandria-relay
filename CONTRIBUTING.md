# Contributing to alexandria-relay

## Commits and pull requests

- Keep unrelated changes in separate commits.
- Explain *why* in the commit body when the reason isn't obvious from the
  diff.

### Commit messages

Every commit subject reads `type: message` or `type(scope): message`:

```
fix(chat): keep the draft when sending fails
docs: correct the migration count
```

| Type | Use it for |
| --- | --- |
| `feat` | New behaviour someone can see or call |
| `fix` | A bug fix |
| `docs` | Documentation only |
| `refactor` | A code change that neither fixes a bug nor adds behaviour |
| `perf` | A performance improvement |
| `test` | Tests only |
| `build` | The build system or dependencies |
| `ci` | CI configuration |
| `security` | Security hardening |
| `i18n` | Translations |
| `release` | Release preparation |
| `revert` | Undoing an earlier commit |
| `style` | Formatting only |
| `chore` | Maintenance that fits nothing above, such as a version bump |

The scope is optional and names the area changed (`chat`, `seed`, `deps`).
Add `!` before the colon for a breaking change: `refactor(api)!: drop v1`.
Merge commits and GitHub's own `Revert "…"` subjects are exempt.

CI checks every commit in a pull request
(`.github/workflows/commit-messages.yml` runs
`scripts/check-commit-messages.sh`). To check each commit as you make it,
install the script as a hook:

```sh
hook="$(git rev-parse --git-path hooks)/commit-msg"
printf '#!/bin/sh\nexec scripts/check-commit-messages.sh --file "$1"\n' > "$hook"
chmod +x "$hook"
```

## Local checks

Run what CI runs before you push:

```sh
cargo fmt --check
cargo clippy --locked -- -D warnings
cargo test --locked
cargo audit            # cargo install cargo-audit --locked
docker build .
```

## CI and releases

`.github/workflows/ci.yml` runs on every push and pull request to `main`:

| Job | Runs |
| --- | --- |
| Check | `cargo check --locked` |
| Clippy | `cargo clippy --locked -- -D warnings` |
| Format | `cargo fmt --check` |
| Test | `cargo test --locked` |
| Dependency audit | `cargo audit` (ignores in `.cargo/audit.toml`) |
| Docker Build | builds the `Dockerfile` with fresh base images |

The **Deploy** job runs only on `v*` tags or manual dispatch, after every
other job passes. It deploys `fly.toml` (Mumbai) and `fly-eu.toml`
(Frankfurt) in parallel, scales each to one machine and makes sure the
`relay_data` volume exists. It needs the `FLY_API_TOKEN` repository secret.

```sh
git tag vX.Y.Z && git push --tags
```

Operating the deployed relays is covered in
[docs/operations.md](docs/operations.md).

## Docs

`scripts/check-docs.sh` runs in CI on every pull request that touches Markdown. It keeps `README.md` under 200 lines, requires a `Status:` line under the title of every file in `docs/`, rejects absolute home-directory paths, and checks relative links. Run it locally before pushing doc changes.

| Status | Meaning |
|---|---|
| `draft` | Proposed, not started |
| `active` | Being implemented |
| `live` | Maintained guide, reference or runbook |
| `implemented` | Finished spec or audit. Frozen: later changes start a new doc |
| `superseded` | Replaced; add `Superseded-by: <path>` |
| `retired` | Describes something that was removed |

Put `Updated: YYYY-MM-DD` on the line after `Status:`.
