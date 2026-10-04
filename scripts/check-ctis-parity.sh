#!/usr/bin/env bash
#
# check-ctis-parity.sh — guard against CTIS schema drift.
#
# sdk-go/pkg/ctis is a hand-maintained copy of the canonical standalone CTIS
# module (github.com/openctemio/ctis), kept separate per RFC-002 so the SDK does
# not pull the whole module graph. The two copies MUST carry the same CTIS schema
# — when they drift, the api (which consumes the canonical module) and the sensor
# (which uses this copy) silently disagree about the data contract. Both have
# happened: a missing FindingStatusSuppressed enum, and earlier, missing struct
# fields (cve_ids / vpr_score / network / evidence).
#
# It compares two things and fails on any difference:
#   1. typed string-constant ENUM sets (e.g. FindingStatus, Severity)
#   2. struct field json tags (catches added/removed/renamed fields)
#   3. FromSARIF: the secret-scanner list, tag caps, sarifTags, isSecretTool and
#      the secret-snippet redaction in sarif.go, and the shared
#      testdata/sarif/betterleaks.sarif and gitleaks-unredacted.sarif samples
#
# Scope: this is a high-signal text check, not a full AST/type comparison (a
# field's Go type change with the same json tag would not be caught). Override
# the canonical ref/source with CTIS_REF / CTIS_TYPES_URL / CTIS_SARIF_REF if
# needed.
set -euo pipefail

# Pinned to the ctis commit this copy mirrors, so a change on ctis main does
# not turn every sdk-go PR red before the copy is synced. Bump it together with
# pkg/ctis (to the release tag once one exists, e.g. v1.3.0).
CTIS_REF="${CTIS_REF:-1af1b6a7c34a45388bb2d28e49b8cbd43c991b11}"
CTIS_TYPES_URL="${CTIS_TYPES_URL:-https://raw.githubusercontent.com/openctemio/ctis/${CTIS_REF}/types.go}"
# FromSARIF is also hand-copied. Its secret-scanner list, its tag caps and the
# shared betterleaks sample are compared against this ctis commit, as are the
# secret-snippet redaction (redactSecretFinding, isRedacted, maskSecret and
# their constants) and the shared gitleaks sample (the ctis#14 commit). Bump it
# with CTIS_REF when pkg/ctis/sarif.go is synced.
CTIS_SARIF_REF="${CTIS_SARIF_REF:-1f96790f7a6f1e730e4ce2071984f1964b4ca526}"
CTIS_RAW_BASE="https://raw.githubusercontent.com/openctemio/ctis/${CTIS_SARIF_REF}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOCAL_TYPES="$ROOT/pkg/ctis/types.go"
LOCAL_SARIF="$ROOT/pkg/ctis/sarif.go"
LOCAL_SARIF_SAMPLE="$ROOT/pkg/ctis/testdata/sarif/betterleaks.sarif"

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

# FromSARIF behaviour that must match ctis: the secretToolNames list and the
# maxSARIFTags / maxSARIFTagLen caps (whitespace-normalised source lines), the
# sarifTags and isSecretTool function bodies, and
# the betterleaks sample both test suites read (byte-identical).
extract_sarif_rules() {
  grep -E '^[[:space:]]*(var secretToolNames|maxSARIFTags|maxSARIFTagLen|const redactedSecret|const secretPrefixLen|const minMaskedPrefixLen)[[:space:]]*=' "$1" \
    | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' | sort
  # The bodies of sarifTags and isSecretTool, which apply them.
  awk '/^func (sarifTags|isSecretTool|redactSecretFinding|isRedacted|maskSecret)\(/,/^}/' "$1"
}
canonical_sarif="$work/sarif.go"
canonical_sample="$work/betterleaks.sarif"
canonical_gitleaks="$work/gitleaks-unredacted.sarif"
if ! curl -fsSL "$CTIS_RAW_BASE/sarif.go" -o "$canonical_sarif" \
  || ! curl -fsSL "$CTIS_RAW_BASE/testdata/sarif/betterleaks.sarif" -o "$canonical_sample" \
  || ! curl -fsSL "$CTIS_RAW_BASE/testdata/sarif/gitleaks-unredacted.sarif" -o "$canonical_gitleaks"; then
  echo "ERROR: failed to fetch canonical CTIS FromSARIF sources from $CTIS_RAW_BASE" >&2
  exit 2
fi
extract_sarif_rules "$canonical_sarif" > "$work/sarif_canon"
extract_sarif_rules "$LOCAL_SARIF" > "$work/sarif_local"
if ! grep -q '^func sarifTags(' "$work/sarif_canon" || ! grep -q '^func isSecretTool(' "$work/sarif_canon" \
  || ! grep -q '^func redactSecretFinding(' "$work/sarif_canon" \
  || [[ $(grep -cE '^(var secretToolNames|maxSARIFTags|maxSARIFTagLen|const redactedSecret|const secretPrefixLen|const minMaskedPrefixLen) ' "$work/sarif_canon") -ne 6 ]]; then
  echo "  DRIFT: could not find secretToolNames, the tag caps, sarifTags or isSecretTool in ctis@${CTIS_SARIF_REF} sarif.go." >&2
  rc=1
elif diff -u "$work/sarif_canon" "$work/sarif_local" > "$work/sarif_diff" 2>&1; then
  echo "  OK: FromSARIF secret scanners, tag caps, sarifTags and isSecretTool in sync."
else
  echo "  DRIFT: FromSARIF secret scanners or tag caps differ from ctis@${CTIS_SARIF_REF}." >&2
  sed 's/^/    /' "$work/sarif_diff" >&2
  rc=1
fi
if cmp -s "$canonical_gitleaks" "$ROOT/pkg/ctis/testdata/sarif/gitleaks-unredacted.sarif"; then
  echo "  OK: gitleaks SARIF sample identical."
else
  echo "  DRIFT: pkg/ctis/testdata/sarif/gitleaks-unredacted.sarif differs from ctis@${CTIS_SARIF_REF}." >&2
  rc=1
fi
if cmp -s "$canonical_sample" "$LOCAL_SARIF_SAMPLE"; then
  echo "  OK: betterleaks SARIF sample identical."
else
  echo "  DRIFT: pkg/ctis/testdata/sarif/betterleaks.sarif differs from ctis@${CTIS_SARIF_REF}." >&2
  rc=1
fi

if [[ $rc -ne 0 ]]; then
  echo "Fix: sync pkg/ctis (types.go, sarif.go, testdata) with github.com/openctemio/ctis (see RFC-002)." >&2
  exit 1
fi
echo "OK: pkg/ctis is in sync with the canonical CTIS schema."
