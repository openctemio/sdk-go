#!/usr/bin/env bash
#
# check-api-compat.sh — weigh every incompatible change of the exported Go
# API against a base revision by the stability tier of its package
# (docs/STABILITY.md; api RFC-029 §8.6: "bump the SDK version and done" only
# holds if a minor release never breaks a sensor that builds against the
# previous one).
#
# Usage: scripts/check-api-compat.sh [BASE_REF]
#   BASE_REF defaults to the latest v* tag reachable from HEAD.
#
# Tiers come from each package comment ("Stability: <Tier>", or a
# "Deprecated:" paragraph; internal/tools/apitiers reads them):
#   Stable, Frozen        an incompatible change fails, unless the break is
#                         declared (API_COMPAT_BREAKING_DECLARED=1: the PR is
#                         labelled breaking-change), then it is a warning
#   Beta                  an incompatible change is a warning
#   Internal-bound,
#   Deprecated            listed for information only
# A public package without a tier fails the check: every package states
# what it promises. Requires apidiff (golang.org/x/exp/cmd/apidiff) on PATH.
# Exits 1 on a failing change or a missing tier; 0 otherwise.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MODULE="$(cd "$ROOT" && GOWORK=off go list -m)"
BASE="${1:-$(git -C "$ROOT" describe --tags --abbrev=0 --match 'v*' 2>/dev/null || true)}"
DECLARED="${API_COMPAT_BREAKING_DECLARED:-0}"
if [ -z "$BASE" ]; then
	echo "check-api-compat: no base revision (no v* tag); nothing to compare" >&2
	exit 0
fi

annotate() { # level message
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		echo "::$1::$2"
	else
		echo "$1: $2" >&2
	fi
}

WORK="$(mktemp -d)"
trap 'git -C "$ROOT" worktree remove --force "$WORK/base" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

git -C "$ROOT" worktree add --detach "$WORK/base" "$BASE" >/dev/null 2>&1
(cd "$WORK/base" && GOWORK=off apidiff -m -w "$WORK/base.export" "$MODULE" 2>/dev/null)
(cd "$ROOT" && GOWORK=off apidiff -m -w "$WORK/head.export" "$MODULE" 2>/dev/null)

# Tiers of HEAD's packages, then of the base's (a package removed by this
# change keeps the tier it had).
(cd "$ROOT" && GOWORK=off go build -o "$WORK/apitiers" ./internal/tools/apitiers)
"$WORK/apitiers" "$ROOT" >"$WORK/head.tiers"
"$WORK/apitiers" "$WORK/base" >"$WORK/base.tiers"

missing="$(awk -F '\t' '$2 == "missing" { print $1 }' "$WORK/head.tiers")"
if [ -n "$missing" ]; then
	while IFS= read -r p; do
		annotate error "$p has no stability tier: add \"Stability: <Stable|Beta|Frozen|Internal-bound> (docs/STABILITY.md).\" to its package comment"
	done <<<"$missing"
	exit 1
fi

INCOMPATIBLE="$(apidiff -m -incompatible "$WORK/base.export" "$WORK/head.export" 2>/dev/null || true)"
# One change is expected in every release and breaks no sensor: the value of
# the release constant pkg/sdk.Version (a release PR sets it to the tag).
# Drop exactly that line; anything else is weighed below.
INCOMPATIBLE="$(printf '%s\n' "$INCOMPATIBLE" |
	grep -Ev '^- (\./|'"$MODULE"'/)pkg/sdk\.Version: value changed from "[0-9]+\.[0-9]+\.[0-9]+" to "[0-9]+\.[0-9]+\.[0-9]+"$' |
	grep '^- ' || true)"
echo "check-api-compat: exported API of $MODULE, $BASE -> HEAD"
apidiff -m "$WORK/base.export" "$WORK/head.export" 2>/dev/null | sed 's/^/  /' || true

fail=0
warned=0
while IFS= read -r line; do
	[ -n "$line" ] || continue
	# "- ./pkg/a/b.Ident: msg", "- <module>/pkg/a/b.Ident: msg" or "- package
	# <module>/pkg/a/b: removed"; package
	# paths have no dots, so the package ends at the first dot or colon.
	rest="${line#- }"
	rest="${rest#package }"
	rest="${rest#./}"
	rest="${rest#"$MODULE"/}"
	pkg="${rest%%[.:]*}"
	tier="$(awk -F '\t' -v p="$pkg" '$1 == p { print $2; exit }' "$WORK/head.tiers")"
	[ -n "$tier" ] || tier="$(awk -F '\t' -v p="$pkg" '$1 == p { print $2; exit }' "$WORK/base.tiers")"
	[ -n "$tier" ] || tier="Stable"
	case "$tier" in
	Stable | Frozen)
		if [ "$DECLARED" = "1" ]; then
			annotate warning "declared breaking change ($tier $pkg): ${line#- }"
			warned=1
		else
			annotate error "incompatible change in a $tier package ($pkg): ${line#- }"
			fail=1
		fi
		;;
	Beta)
		annotate warning "incompatible change in a Beta package ($pkg): ${line#- }; add an upgrade note (changelog.d, \"### Upgrade notes\")"
		warned=1
		;;
	*)
		echo "  ignored ($tier $pkg): ${line#- }"
		;;
	esac
done <<<"$INCOMPATIBLE"

if [ "$fail" -eq 1 ]; then
	echo "check-api-compat: a sensor built against $BASE would need edits. Keep the old identifier" >&2
	echo "(alias or wrapper, marked // Deprecated:) or, if the break is intended, label the PR" >&2
	echo "breaking-change and add a changelog.d/<slug>.md fragment with an \"### Upgrade notes\" section." >&2
	exit 1
fi
if [ "$warned" -eq 1 ]; then
	echo "check-api-compat: incompatible changes outside the Stable promise (warnings above)."
else
	echo "check-api-compat: no incompatible change in a Stable or Beta package."
fi
