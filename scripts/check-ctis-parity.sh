#!/usr/bin/env bash
#
# check-ctis-parity.sh — guard against CTIS schema drift.
#
# sdk-go/pkg/ctis is a hand-maintained copy of the canonical standalone CTIS
# module (github.com/openctemio/ctis), kept separate per RFC-002 so the SDK does
# not pull the whole module graph. The two copies MUST carry the same CTIS schema
# — when they drift, the api (which consumes the canonical module) and the agent
# (which uses this copy) silently disagree about the data contract. Both have
# happened: a missing FindingStatusSuppressed enum, and earlier, missing struct
# fields (cve_ids / vpr_score / network / evidence).
#
# It compares two things and fails on any difference:
#   1. typed string-constant ENUM sets (e.g. FindingStatus, Severity)
#   2. struct field json tags (catches added/removed/renamed fields)
#
# Scope: this is a high-signal text check, not a full AST/type comparison (a
# field's Go type change with the same json tag would not be caught). Override
# the canonical ref/source with CTIS_REF / CTIS_TYPES_URL if needed.
set -euo pipefail

CTIS_REF="${CTIS_REF:-main}"
CTIS_TYPES_URL="${CTIS_TYPES_URL:-https://raw.githubusercontent.com/openctemio/ctis/${CTIS_REF}/types.go}"
LOCAL_TYPES="$(cd "$(dirname "$0")/.." && pwd)/pkg/ctis/types.go"

if [[ ! -f "$LOCAL_TYPES" ]]; then
  echo "ERROR: local CTIS types not found at $LOCAL_TYPES" >&2
  exit 2
fi

canonical="$(mktemp)"
work="$(mktemp -d)"
trap 'rm -rf "$canonical" "$work" 2>/dev/null || true' EXIT

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

# Extract struct field json tag names (the part before any ",omitempty"),
# dropping the "-" skip tag. A multiset (with counts) so adding a field whose
# json name is reused elsewhere still changes the tally.
extract_fields() {
  grep -oE '`json:"[^"]*"' "$1" \
    | sed -E 's/`json:"//; s/"$//; s/,.*//' \
    | grep -vE '^-?$' \
    | sort | uniq -c | sed -E 's/^[[:space:]]+//'
}

rc=0

compare() { # label, extractor, noun
  local label="$1" fn="$2" noun="$3"
  "$fn" "$canonical" > "$work/canon"
  "$fn" "$LOCAL_TYPES" > "$work/local"
  if diff -u "$work/canon" "$work/local" > "$work/diff" 2>&1; then
    echo "  OK: $label in sync ($(wc -l < "$work/canon" | tr -d ' ') $noun)."
  else
    echo "  DRIFT: $label differ from canonical ctis@${CTIS_REF}." >&2
    echo "    '-' = in canonical but MISSING here; '+' = present here but not in canonical." >&2
    sed 's/^/    /' "$work/diff" >&2
    rc=1
  fi
}

echo "Checking CTIS parity vs canonical ctis@${CTIS_REF} ..."
compare "enum constants" extract_consts "constants"
compare "struct json fields" extract_fields "fields"

if [[ $rc -ne 0 ]]; then
  echo "Fix: sync pkg/ctis/types.go with github.com/openctemio/ctis (see RFC-002)." >&2
  exit 1
fi
echo "OK: pkg/ctis is in sync with the canonical CTIS schema."
