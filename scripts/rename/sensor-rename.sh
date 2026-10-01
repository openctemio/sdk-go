#!/usr/bin/env bash
# =============================================================================
# sensor-rename.sh — the mechanical half of the agent → sensor rename of the
# SDK (RFC-023 §9.5). Re-runnable: on a tree that is already renamed it is a
# no-op, so a branch opened before the rename catches up by rebasing and
# running it.
#
# What it does, in order:
#   1. type-aware rename of every Go identifier, package name and comment
#      (scripts/rename/sensorrename, built on internal/sensorrename — the same
#      code cmd/sensor-migrate runs on third-party modules);
#   2. git mv of every .go file with "agent" in its path;
#   3. goimports on every changed file, then build + vet as a gate.
#
# What it does NOT do: string literals, struct tags, the protocol v1 schema
# (proto/), docs. The wire is protocol v1 and frozen
# (pkg/sensorproto/legacyv1); persisted formats and docs move in reviewed,
# hand-written commits.
#
# Usage:  scripts/rename/sensor-rename.sh            (from the sdk-go repo root)
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
export GOWORK=off

echo "sensor-rename: renaming identifiers, comments and files…"
go run ./scripts/rename/sensorrename -dir "$ROOT"

echo "sensor-rename: goimports…"
changed=$(git diff --name-only --diff-filter=AMR -- '*.go'; git diff --cached --name-only --diff-filter=AMR -- '*.go'; git ls-files --others --exclude-standard -- '*.go')
changed=$(printf '%s\n' "$changed" | sort -u | grep -v '^$' || true)
if [ -n "$changed" ]; then
  # shellcheck disable=SC2086
  if command -v goimports >/dev/null; then goimports -w $changed; else go run golang.org/x/tools/cmd/goimports -w $changed; fi
fi

echo "sensor-rename: build + vet gate…"
go build ./...
go vet ./...
echo "sensor-rename: done."
