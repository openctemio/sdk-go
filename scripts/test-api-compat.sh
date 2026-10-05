#!/usr/bin/env bash
#
# test-api-compat.sh — tests of scripts/check-api-compat.sh on a scratch
# module: a break in a Stable package fails (and passes when declared), a
# break in a Beta package warns, breaks in Internal-bound and Deprecated
# packages are ignored, and a package without a tier fails. Needs apidiff.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
export GOWORK=off GOFLAGS=-mod=mod

m="$T/m"
mkdir -p "$m/scripts" "$m/internal/tools/apitiers"
cp "$ROOT/scripts/check-api-compat.sh" "$m/scripts/"
cp "$ROOT/internal/tools/apitiers/main.go" "$m/internal/tools/apitiers/"
printf 'module example.com/m\n\ngo 1.22\n' >"$m/go.mod"

pkg() { # dir comment-lines...
	local dir="$1"
	shift
	mkdir -p "$m/$dir"
	{
		for l in "$@"; do echo "// $l"; done
		echo "package ${dir##*/}"
		echo
		echo "// F is exported."
		echo "func F() {}"
	} >"$m/$dir/x.go"
}
pkg pkg/stable "Package stable is stable." "" "Stability: Stable (docs/STABILITY.md)."
pkg pkg/frozen "Package frozen is frozen." "" "Stability: Frozen (docs/STABILITY.md)."
pkg pkg/beta "Package beta is beta." "" "Stability: Beta (docs/STABILITY.md)."
pkg pkg/bound "Package bound is internal-bound." "" "Stability: Internal-bound (docs/STABILITY.md)."
pkg pkg/old "Package old is old." "" "Deprecated: use pkg/stable."

git -C "$m" init -q -b main
git -C "$m" -c user.name=t -c user.email=t@example.invalid add -A
git -C "$m" -c user.name=t -c user.email=t@example.invalid commit -qm base
git -C "$m" tag v0.1.0

failed=0
check() { # name want-rc [env...] -- expect-substring
	local name="$1" want="$2" needle="$3"
	shift 3
	local out rc
	set +e
	out="$(cd "$m" && env -u GITHUB_ACTIONS "$@" bash scripts/check-api-compat.sh v0.1.0 2>&1)"
	rc=$?
	set -e
	if [ "$rc" != "$want" ] || [[ "$out" != *"$needle"* ]]; then
		echo "FAIL $name: rc=$rc (want $want), want output containing: $needle"
		printf "%s\n" "$out" | sed "s/^/    /"
		failed=1
	else
		echo "ok   $name"
	fi
}
breakpkg() { sed -i 's/^func F() {}$/func G() {}/' "$m/$1/x.go"; }
reset() { git -C "$m" checkout -q -- . && git -C "$m" clean -qfd; }

check "no change" 0 "no incompatible change" X=1
breakpkg pkg/stable
check "Stable break fails" 1 "error: incompatible change in a Stable package (pkg/stable)" X=1
check "Stable break declared" 0 "warning: declared breaking change (Stable pkg/stable)" API_COMPAT_BREAKING_DECLARED=1
reset
breakpkg pkg/frozen
check "Frozen break fails" 1 "incompatible change in a Frozen package (pkg/frozen)" X=1
reset
breakpkg pkg/beta
check "Beta break warns" 0 "warning: incompatible change in a Beta package (pkg/beta)" X=1
reset
breakpkg pkg/bound
check "Internal-bound break ignored" 0 "ignored (Internal-bound pkg/bound)" X=1
reset
breakpkg pkg/old
check "Deprecated break ignored" 0 "ignored (Deprecated pkg/old)" X=1
reset
rm -r "$m/pkg/stable"
check "removed Stable package fails (tier from the base)" 1 "Stable package (pkg/stable)" X=1
reset
pkg pkg/untiered "Package untiered says nothing."
check "package without a tier fails" 1 "pkg/untiered has no stability tier" X=1
reset
check "annotations in Actions" 0 "" GITHUB_ACTIONS=true
breakpkg pkg/beta
check "Actions warning annotation" 0 "::warning::incompatible change in a Beta package" GITHUB_ACTIONS=true
reset

[ "$failed" -eq 0 ] && echo "all api-compat tests passed"
exit "$failed"
