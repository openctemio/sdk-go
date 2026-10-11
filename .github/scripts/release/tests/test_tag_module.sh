#!/usr/bin/env bash
# Tests for tag-module.sh: nested module tags <dir>/vX.Y.Z.
# shellcheck source-path=SCRIPTDIR
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=testlib.sh
source "$HERE/testlib.sh"
TAG="$RELEASE_DIR/tag-module.sh"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
git init -q --bare -b main "$tmp/origin.git"
r="$tmp/sdk"
new_repo "$r"
git -C "$r" remote add origin "$tmp/origin.git"
printf 'module github.com/openctemio/sdk-go\n\ngo 1.26.0\n' >"$r/go.mod"
mkdir -p "$r/pkg/transfer"
printf 'module github.com/openctemio/sdk-go/pkg/transfer\n\ngo 1.26.0\n' >"$r/pkg/transfer/go.mod"
git -C "$r" add -A
git -C "$r" commit -q -m "feat: nested module"
git -C "$r" tag v0.19.0
git -C "$r" push -q origin main --tags

assert_rc "module: bad version" 2 bash "$TAG" --repo "$r" --module pkg/transfer --version 0.1.0 --commit HEAD
assert_rc "module: bad module path" 2 bash "$TAG" --repo "$r" --module ../x --version v0.1.0 --commit HEAD
assert_rc "module: no go.mod in that directory" 1 bash "$TAG" --repo "$r" --module pkg/other --version v0.1.0 --commit HEAD
out="$(bash "$TAG" --repo "$r" --module pkg/transfer --version v0.1.0 --commit HEAD --push 2>&1)"; rc=$?
assert_eq "module: tag (exit code)" 0 "$rc"
assert_contains "module: tag name" "TAG=pkg/transfer/v0.1.0" "$out"
assert_contains "module: pushed" "refs/tags/pkg/transfer/v0.1.0" "$(git -C "$r" ls-remote --tags origin)"
assert_rc "module: twice refused" 1 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.1.0 --commit HEAD
assert_rc "module: not greater refused" 1 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.0.9 --commit HEAD
# The root release tags are not module releases: v0.19.0 does not block v0.2.0.
assert_rc "module: root tags ignored" 0 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.2.0 --commit HEAD

printf 'module github.com/openctemio/sdk-go/pkg/transfer\n\ngo 1.26.0\n\nreplace github.com/openctemio/sdk-go => ../..\n' >"$r/pkg/transfer/go.mod"
git -C "$r" commit -q -am "chore: replace"
git -C "$r" push -q origin main
assert_rc "module: replace directive refused" 1 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.3.0 --commit HEAD

printf 'module github.com/openctemio/sdk-go/wrong\n\ngo 1.26.0\n' >"$r/pkg/transfer/go.mod"
git -C "$r" commit -q -am "chore: wrong path"
git -C "$r" push -q origin main
assert_rc "module: wrong module path refused" 1 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.3.0 --commit HEAD

git -C "$r" checkout -q -b side
printf 'module github.com/openctemio/sdk-go/pkg/transfer\n\ngo 1.26.0\n' >"$r/pkg/transfer/go.mod"
git -C "$r" commit -q -am "fix: off main"
assert_rc "module: commit not on main refused" 1 bash "$TAG" --repo "$r" --module pkg/transfer --version v0.3.0 --commit HEAD

finish
