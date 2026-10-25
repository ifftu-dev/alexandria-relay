#!/usr/bin/env bash
# Tests for check-commit-messages.sh against a throwaway repository.
set -euo pipefail
check="$(cd "$(dirname "$0")" && pwd)/check-commit-messages.sh"
repo=$(mktemp -d)
trap 'rm -rf "$repo"' EXIT
cd "$repo"
git init -q
git config user.name test
git config user.email test@example.invalid
git config commit.gpgsign false
commit() { git commit -q --allow-empty -m "$1"; }
fails=0
expect() {
  local want=$1 subject=$2
  printf '%s\n' "$subject" > msg
  if "$check" --file msg 2>/dev/null; then got=pass; else got=fail; fi
  if [ "$got" != "$want" ]; then echo "FAIL: expected $want: $subject"; fails=1; fi
}

for ok in 'feat: add leadership skills' 'fix(chat): keep the draft' 'docs: note it' \
  'refactor(seed)!: drop the old installer' 'ci(release): pin the runner' \
  'i18n(chat): translate strings' 'chore(deps): bump rusqlite' \
  'Revert "feat: add leadership skills"' 'Merge branch '"'"'main'"'"' into topic'; do
  expect pass "$ok"
done
for bad in 'Add leadership skills' 'feature: add leadership skills' 'feat:add it' \
  'feat : add it' 'Feat: add it' 'feat(): add it' 'feat(chat) add it' 'wip' '' \
  'fixup! feat: add it' 'squash! fix: it'; do
  expect fail "$bad"
done
printf '# comment\n\nfix: from a hook message file\n\nbody\n' > msg
"$check" --file msg >/dev/null 2>&1 || { echo "FAIL: hook file with leading comment"; fails=1; }

commit 'chore: base'
base=$(git rev-parse HEAD)
commit 'feat: one'
git checkout -q -b side
commit 'fix: on a side branch'
git checkout -q -
git merge -q --no-ff side -m "Merge branch 'side'"
commit 'docs(readme): two'
"$check" "$base" HEAD >/dev/null 2>&1 || { echo "FAIL: clean range rejected"; fails=1; }
commit 'Update stuff'
if "$check" "$base" HEAD >/dev/null 2>&1; then echo "FAIL: bad range accepted"; fails=1; fi
out=$("$check" "$base" HEAD 2>&1 || true)
case $out in *"Update stuff"*) ;; *) echo "FAIL: offending subject not named"; fails=1 ;; esac

[ "$fails" = 0 ] && echo "check-commit-messages tests passed"
exit "$fails"
