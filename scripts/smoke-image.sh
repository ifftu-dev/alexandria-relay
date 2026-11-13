#!/usr/bin/env bash
# Smoke-tests a built relay image without starting the relay.
#
#   scripts/smoke-image.sh IMAGE [PLATFORM]
#
# Checks that the image declares a non-root user, that the data directory the
# image points the relay at is writable by that user, and that the binary runs
# (`--generate-key` prints a PeerId). PLATFORM (e.g. linux/arm64) is passed to
# `docker run` so one host can check every architecture it can emulate.
set -euo pipefail

image="${1:?usage: scripts/smoke-image.sh IMAGE [PLATFORM]}"
platform_args=()
if [ -n "${2:-}" ]; then
  platform_args=(--platform "$2")
fi

failures=0
fail() {
  printf 'FAIL: %s\n' "$1" >&2
  failures=$((failures + 1))
}

user=$(docker image inspect --format '{{.Config.User}}' "$image")
case "$user" in
  '' | root | 0 | 0:* | root:*) fail "image runs as root (User='$user')" ;;
  *) echo "ok: image user is $user" ;;
esac

if docker run --rm "${platform_args[@]}" --entrypoint sh "$image" \
  -c 'test -n "$RELAY_DATA_DIR" && touch "$RELAY_DATA_DIR/.write-test"'; then
  echo "ok: RELAY_DATA_DIR is set and writable"
else
  fail "RELAY_DATA_DIR is unset or not writable by the image user"
fi

if out=$(docker run --rm "${platform_args[@]}" "$image" --generate-key) &&
  printf '%s\n' "$out" | grep -q 'PeerId:'; then
  echo "ok: --generate-key prints a PeerId"
else
  fail "--generate-key did not print a PeerId"
fi

if [ "$failures" -gt 0 ]; then
  exit 1
fi
echo "Image OK."
