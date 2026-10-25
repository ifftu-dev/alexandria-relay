#!/usr/bin/env bash
# Checks that commit subjects read `type: message` or `type(scope): message`.
#
#   scripts/check-commit-messages.sh <base> <head>   every non-merge commit in base..head
#   scripts/check-commit-messages.sh --file <path>   one message, e.g. as a commit-msg hook
#
# Kept identical across the Alexandria repositories; CONTRIBUTING.md explains
# the format and when to use each type.
set -euo pipefail

TYPES='feat|fix|docs|chore|refactor|test|perf|ci|build|style|revert|security|i18n|release'
PATTERN="^(${TYPES})(\([A-Za-z0-9._/-]+\))?!?: [^[:space:]]"
# Subjects git and GitHub write themselves.
GENERATED='^(Revert "|Merge |fixup! |squash! |amend! )'

valid() {
  [[ "$1" =~ $PATTERN ]] || { [[ "$1" =~ $GENERATED ]] && [[ ! "$1" =~ ^(fixup|squash|amend)!\  ]]; }
}

explain() {
  cat >&2 <<HELP

Commit subjects must read  type: message  or  type(scope): message
  types: ${TYPES//|/, }
  e.g.   fix(chat): keep the draft when sending fails
Reword with: git commit --amend  (latest commit)  or  git rebase -i <base>  (older ones)
HELP
}

if [ "${1:-}" = --file ]; then
  subject=$(grep -v '^#' "${2:?message file}" | sed -n '/[^[:space:]]/{p;q;}')
  if valid "$subject"; then exit 0; fi
  echo "bad commit subject: $subject" >&2
  explain
  exit 1
fi

base=${1:?usage: $0 <base> <head> | --file <path>}
head=${2:?usage: $0 <base> <head> | --file <path>}
bad=0
while IFS= read -r line; do
  [ -n "$line" ] || continue
  sha=${line%% *}
  subject=${line#* }
  if ! valid "$subject"; then
    echo "bad commit subject: ${sha:0:12} $subject" >&2
    bad=1
  fi
done < <(git log --no-merges --format='%H %s' "$base..$head")
if [ "$bad" = 1 ]; then
  explain
  exit 1
fi
echo "commit subjects ok"
