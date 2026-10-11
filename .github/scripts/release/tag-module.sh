#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# tag-module.sh: tag a nested Go module of sdk-go (a directory with its own
# go.mod, such as pkg/transfer) as <dir>/vX.Y.Z, the tag form the Go module
# proxy resolves for github.com/openctemio/sdk-go/<dir>. sdk-go only; the root
# module keeps its vX.Y.Z tags from tag-release.sh.
#
#   tag-module.sh --module DIR --version vX.Y.Z --commit SHA [--push] [--remote origin] [--repo DIR]
#
# Refuses unless the version is vX.Y.Z and greater than every DIR/v* tag, the
# tag does not exist (locally or on the remote), the commit is on main, and at
# that commit DIR/go.mod declares github.com/openctemio/sdk-go/DIR and has no
# replace directive (a published go.mod must resolve from tags alone).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

MODULE=""
VERSION=""
COMMIT=""
PUSH=0
REMOTE="origin"
REPO="."
while [[ $# -gt 0 ]]; do
  case "$1" in
    --module) MODULE="$2"; shift ;;
    --version) VERSION="$2"; shift ;;
    --commit) COMMIT="$2"; shift ;;
    --push) PUSH=1 ;;
    --remote) REMOTE="$2"; shift ;;
    --repo) REPO="$2"; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
die() { echo "REFUSING: $*" >&2; exit 1; }
g() { git -C "$REPO" "$@"; }

[[ "$MODULE" =~ ^[a-z0-9_]+(/[a-z0-9_]+)*$ ]] || { echo "--module must be a relative directory such as pkg/transfer, got '$MODULE'" >&2; exit 2; }
rel_is_version "$VERSION" || { echo "--version must be vX.Y.Z, got '$VERSION'" >&2; exit 2; }
[[ -n "$COMMIT" ]] || { echo "--commit is required" >&2; exit 2; }
TAG="$MODULE/$VERSION"
g fetch --quiet --tags "$REMOTE" "+refs/heads/main:refs/remotes/$REMOTE/main"
COMMIT="$(g rev-parse --verify "$COMMIT^{commit}")"

g rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "tag $TAG already exists"
g ls-remote --exit-code --tags "$REMOTE" "refs/tags/$TAG" >/dev/null 2>&1 && die "tag $TAG already exists on $REMOTE"
last="$(g tag -l "$MODULE/v*" | sed "s|^$MODULE/||" | grep -E "$REL_VERSION_RE" | sort -V | tail -n 1 || true)"
if [[ -n "$last" ]] && ! rel_version_gt "$VERSION" "$last"; then
  die "$VERSION is not greater than the last $MODULE release $last"
fi
g merge-base --is-ancestor "$COMMIT" "refs/remotes/$REMOTE/main" || die "$COMMIT is not on main"

gomod="$(g show "$COMMIT:$MODULE/go.mod" 2>/dev/null)" || die "no $MODULE/go.mod at $COMMIT"
root="$(g show "$COMMIT:go.mod" 2>/dev/null | sed -nE 's/^module[[:space:]]+([^[:space:]]+).*/\1/p')"
[[ -n "$root" ]] || die "no root go.mod at $COMMIT"
want="$root/$MODULE"
have="$(sed -nE 's/^module[[:space:]]+([^[:space:]]+).*/\1/p' <<<"$gomod")"
[[ "$have" == "$want" ]] || die "$MODULE/go.mod at $COMMIT declares '$have', not $want"
grep -qE '^[[:space:]]*replace([[:space:]]|\(|$)' <<<"$gomod" && die "$MODULE/go.mod at $COMMIT has a replace directive"

g -c user.name="${GIT_AUTHOR_NAME:-openctem-release}" -c user.email="${GIT_AUTHOR_EMAIL:-release@openctem.invalid}" \
  tag -a "$TAG" "$COMMIT" -m "$TAG"
echo "tagged $TAG at $COMMIT" >&2
if [[ $PUSH -eq 1 ]]; then
  g push --quiet "$REMOTE" "refs/tags/$TAG"
  echo "pushed $TAG" >&2
fi
echo "TAG=$TAG"
echo "COMMIT=$COMMIT"
