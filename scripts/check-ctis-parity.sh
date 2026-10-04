#!/usr/bin/env bash
#
# check-ctis-parity.sh — pkg/ctis must be the CTIS module, not a copy of it.
#
# pkg/ctis re-exports github.com/openctemio/ctis (type aliases, constants and
# wrapper functions in zz_generated_aliases.go, written by
# pkg/ctis/internal/genalias from the version go.mod requires). This check
# fails when:
#   1. the generated file is stale (ctis was bumped in go.mod, or the file was
#      edited by hand): run `go generate ./pkg/ctis`;
#   2. pkg/ctis declares a struct type of its own that is not on the SDK-only
#      list below, i.e. a hand copy of part of the model is creeping back.
#      This is what drifted before (an invalid recon scope, Trivy CVEs typed as
#      misconfigurations, unknown tools filed as secret scanners).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PKG="$ROOT/pkg/ctis"
GENERATED="$PKG/zz_generated_aliases.go"

# Struct types pkg/ctis may declare itself: SDK behavior around the module's
# types, not part of the CTIS model.
# SARIFLog/SARIFRun: the module's SARIF root types plus versionControlProvenance.
SDK_ONLY_STRUCTS="FindingAssetError SARIFVersionControlDetails SARIFLog SARIFRun"

cd "$ROOT"
export GOWORK=off

go mod download github.com/openctemio/ctis

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

(cd "$PKG" && go run ./internal/genalias "$tmp/aliases.go")
if ! diff -u "$GENERATED" "$tmp/aliases.go"; then
  echo "ERROR: pkg/ctis/zz_generated_aliases.go is stale; run: go generate ./pkg/ctis" >&2
  exit 1
fi

fail=0
while IFS= read -r name; do
  [[ -z "$name" ]] && continue
  if [[ " $SDK_ONLY_STRUCTS " != *" $name "* ]]; then
    echo "ERROR: pkg/ctis declares struct $name: re-export it from github.com/openctemio/ctis instead of copying it" >&2
    fail=1
  fi
done < <(find "$PKG" -maxdepth 1 -name '*.go' ! -name '*_test.go' ! -name 'zz_generated_aliases.go' -print0 \
  | xargs -0 grep -hoE '^type [A-Z][A-Za-z0-9_]* struct' | awk '{print $2}' | sort -u)

if [[ $fail -ne 0 ]]; then
  exit 1
fi

version="$(go list -m -f '{{.Version}}' github.com/openctemio/ctis)"
echo "OK: pkg/ctis re-exports github.com/openctemio/ctis $version"
