#!/usr/bin/env bash
# Keeps the repository's Markdown small, current and portable.
#
#   scripts/check-docs.sh            check every tracked .md file
#
# Rules:
#   1. README.md stays within README_MAX_LINES (default 200).
#   2. Every docs/**/*.md opens with a `Status:` or `Triage:` line in its first
#      12 lines. Index files (README.md), docs/adr/ and docs/agents/ are exempt.
#   3. No absolute home-directory paths in committed docs.
#   4. Relative links point at files that exist.
#
# Third-party Markdown (patches/, vendor/, node_modules/, build output, blog
# content) is skipped. Kept identical across the Alexandria repositories;
# CONTRIBUTING.md explains the Status values.
set -euo pipefail

README_MAX_LINES="${README_MAX_LINES:-200}"
SKIP='^(patches|vendor|node_modules|dist|content/blog)/|/(vendor|node_modules|build|dist)/'

cd "$(git rev-parse --show-toplevel)"
failures=0
fail() {
  printf '%s\n' "$1" >&2
  failures=$((failures + 1))
}

files=$(git ls-files -- '*.md' | grep -Ev "$SKIP" || true)

if [ -f README.md ]; then
  lines=$(wc -l < README.md | tr -d ' ')
  if [ "$lines" -gt "$README_MAX_LINES" ]; then
    fail "README.md: $lines lines (limit $README_MAX_LINES). Move detail into docs/ and link it."
  fi
fi

while IFS= read -r f; do
  [ -n "$f" ] || continue

  case "$f" in
    docs/adr/* | docs/agents/* | */README.md | README.md) ;;
    docs/*)
      if ! head -n 12 "$f" | grep -Eq '^(Status|Triage):'; then
        fail "$f: no 'Status:' or 'Triage:' line under the title."
      fi
      ;;
  esac

  if grep -nE '(/Users/|/home/)[A-Za-z0-9._-]+/' "$f" > /tmp/check-docs-paths.$$; then
    while IFS= read -r hit; do
      fail "$f:${hit%%:*}: absolute home-directory path. Use a repo-relative path."
    done < /tmp/check-docs-paths.$$
  fi

  dir=$(dirname "$f")
  # Inline links and images: ](target) — skip URLs, mail links, pure anchors,
  # and examples inside fenced blocks or `code spans` (line numbers kept).
  { awk '/^[[:space:]]*(```|~~~)/ { fence = !fence; print ""; next }
         fence { print ""; next }
         { gsub(/`[^`]*`/, ""); print }' "$f" | grep -noE '\]\([^) ]+\)' || true; } | while IFS= read -r hit; do
    line=${hit%%:*}
    target=${hit#*](}
    target=${target%)}
    target=${target%%#*}
    case "$target" in
      '' | *://* | mailto:* | tel:* | '<'*) continue ;;
    esac
    if [ "${target#/}" != "$target" ]; then
      resolved=".${target}"
    else
      resolved="$dir/$target"
    fi
    if [ ! -e "$resolved" ]; then
      printf '%s\n' "$f:$line: broken link to $target" >&2
      echo x
    fi
  done > /tmp/check-docs-links.$$
  failures=$((failures + $(wc -l < /tmp/check-docs-links.$$ | tr -d ' ')))
done <<< "$files"

rm -f /tmp/check-docs-paths.$$ /tmp/check-docs-links.$$

if [ "$failures" -gt 0 ]; then
  printf '\n%s problem(s) in Markdown docs.\n' "$failures" >&2
  exit 1
fi
echo "Docs OK."
