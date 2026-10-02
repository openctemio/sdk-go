#!/usr/bin/env bash
#
# check-api-compat.sh — fail when the exported Go API is not backward
# compatible with a base revision (api RFC-029 §8.6: "bump the SDK version
# and done" only holds if a minor release never breaks a sensor that builds
# against the previous one).
#
# Usage: scripts/check-api-compat.sh [BASE_REF]
#   BASE_REF defaults to the latest v* tag reachable from HEAD.
#
# Requires apidiff (golang.org/x/exp/cmd/apidiff) on PATH. Prints every
# incompatible change and exits 1 when there is one; exits 0 otherwise.
# Compatible additions are listed for information.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE="$(cd "$ROOT" && GOWORK=off go list -m)"
BASE="${1:-$(git -C "$ROOT" describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)}"
if [ -z "$BASE" ]; then
	echo "check-api-compat: no base revision (no v* tag); nothing to compare" >&2
	exit 0
fi

WORK="$(mktemp -d)"
trap 'git -C "$ROOT" worktree remove --force "$WORK/base" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

git -C "$ROOT" worktree add --detach "$WORK/base" "$BASE" >/dev/null 2>&1
(cd "$WORK/base" && GOWORK=off apidiff -m -w "$WORK/base.export" "$MODULE")
(cd "$ROOT" && GOWORK=off apidiff -m -w "$WORK/head.export" "$MODULE")

INCOMPATIBLE="$(apidiff -m -incompatible "$WORK/base.export" "$WORK/head.export" || true)"
# One change is expected in every release and breaks no sensor: the value of
# the release constant pkg/sdk.Version (a release PR sets it to the tag).
# Drop exactly that line; anything else still fails.
INCOMPATIBLE="$(printf '%s\n' "$INCOMPATIBLE" |
	grep -Ev '^- (\./|'"$MODULE"'/)pkg/sdk\.Version: value changed from "[0-9]+\.[0-9]+\.[0-9]+" to "[0-9]+\.[0-9]+\.[0-9]+"$' |
	grep -v '^[[:space:]]*$' || true)"
echo "check-api-compat: exported API of $MODULE, $BASE -> HEAD"
apidiff -m "$WORK/base.export" "$WORK/head.export" | sed 's/^/  /' || true
if [ -n "$INCOMPATIBLE" ]; then
	echo "check-api-compat: INCOMPATIBLE changes against $BASE:" >&2
	echo "$INCOMPATIBLE" | sed 's/^/  /' >&2
	echo "A sensor built against $BASE would need edits. Keep the old identifier (alias or" >&2
	echo "wrapper, marked // Deprecated:) or, if the break is intended, label the PR" >&2
	echo "breaking-change and add an \"Upgrade notes\" entry to CHANGELOG.md." >&2
	exit 1
fi
echo "check-api-compat: no incompatible change."
