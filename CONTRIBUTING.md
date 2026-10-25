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
