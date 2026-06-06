#!/usr/bin/env bash
#
# check-ctis-parity.sh — guard against CTIS schema drift.
#
# sdk-go/pkg/ctis is a hand-maintained copy of the canonical standalone CTIS
# module (github.com/openctemio/ctis), kept separate per RFC-002 so the SDK does
# not pull the whole module graph. The two copies MUST carry the same CTIS schema
# — when they drift, the api (which consumes the canonical module) and the agent
# (which uses this copy) silently disagree about the data contract. That actually
# happened in 2026-06 (this copy was missing FindingStatusSuppressed).
#
# This guard compares the typed string-constant ENUM sets of the two copies (the
# class of declaration that drifts in practice) and fails on any difference.
#
# Override the canonical ref/source with CTIS_REF / CTIS_TYPES_URL if needed.
set -euo pipefail

CTIS_REF="${CTIS_REF:-main}"
CTIS_TYPES_URL="${CTIS_TYPES_URL:-https://raw.githubusercontent.com/openctemio/ctis/${CTIS_REF}/types.go}"
LOCAL_TYPES="$(cd "$(dirname "$0")/.." && pwd)/pkg/ctis/types.go"

if [[ ! -f "$LOCAL_TYPES" ]]; then
  echo "ERROR: local CTIS types not found at $LOCAL_TYPES" >&2
  exit 2
fi

canonical="$(mktemp)"
trap 'rm -f "$canonical" "$canonical.consts" "$LOCAL_TYPES.consts" 2>/dev/null || true' EXIT

# Fail closed if we cannot fetch the canonical source — an unverifiable copy is
# treated as a failure, not a silent pass.
if ! curl -fsSL "$CTIS_TYPES_URL" -o "$canonical"; then
  echo "ERROR: failed to fetch canonical CTIS types from $CTIS_TYPES_URL" >&2
  exit 2
fi

# Extract `Identifier ... = "value"` declarations as `Identifier="value"`,
# tolerant of whitespace and of the type token being present or omitted.
extract_consts() {
  grep -oE '^[[:space:]]+[A-Z][A-Za-z0-9_]*[[:space:]].*=[[:space:]]*"[^"]*"' "$1" \
    | sed -E 's/^[[:space:]]+([A-Za-z0-9_]+).*=[[:space:]]*("[^"]*")/\1=\2/' \
    | sort -u
}

extract_consts "$canonical" > "$canonical.consts"
extract_consts "$LOCAL_TYPES" > "$LOCAL_TYPES.consts"

if diff -u "$canonical.consts" "$LOCAL_TYPES.consts" > /tmp/ctis_parity.diff 2>&1; then
  count="$(wc -l < "$canonical.consts" | tr -d ' ')"
  echo "OK: CTIS enum constants in sync with canonical ctis@${CTIS_REF} (${count} constants)."
  exit 0
fi

echo "DRIFT DETECTED: sdk-go/pkg/ctis enum constants differ from canonical ctis@${CTIS_REF}." >&2
echo "  '-' = in canonical but MISSING here; '+' = present here but not in canonical." >&2
echo >&2
cat /tmp/ctis_parity.diff >&2
echo >&2
echo "Fix: sync pkg/ctis/types.go with github.com/openctemio/ctis (see RFC-002)." >&2
exit 1
