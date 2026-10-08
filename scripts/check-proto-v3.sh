#!/usr/bin/env bash
# Sensor protocol v3 (openctem api RFC-059) in sdk-go:
#   1. proto/sensor-v3 is a byte-for-byte copy of the platform's
#      api/proto/openctem/sensor/v3/sensor.proto (openctemio/openctem,
#      branch PROTO_UPSTREAM_REF, default develop);
#   2. buf lint;
#   3. the committed pkg/sensorproto/v3 is what buf generate writes.
#
# Usage: scripts/check-proto-v3.sh            (checks)
#        scripts/check-proto-v3.sh --generate (regenerate only)
set -euo pipefail

BUF_VERSION=1.73.0
BUF_SHA256=8f2986298ad08f0cc1bf999b9797b7c383adf32d7edf0f73d6f1e1a701baeac1
PROTOC_GEN_GO_VERSION=v1.36.12
PROTOC_GEN_CONNECT_GO_VERSION=v1.21.0
UPSTREAM_REF="${PROTO_UPSTREAM_REF:-develop}"
UPSTREAM="https://raw.githubusercontent.com/openctemio/openctem/${UPSTREAM_REF}/api/proto/openctem/sensor/v3/sensor.proto"

cd "$(dirname "$0")/.."
root="$(pwd)"
tools="${PROTO_TOOLS_DIR:-$root/.proto-tools}"
mkdir -p "$tools"
export PATH="$tools:$PATH"

if ! "$tools/buf" --version 2>/dev/null | grep -qx "$BUF_VERSION"; then
  case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)
      curl -fsSL -o "$tools/buf.tmp" "https://github.com/bufbuild/buf/releases/download/v${BUF_VERSION}/buf-Linux-x86_64"
      echo "${BUF_SHA256}  $tools/buf.tmp" | sha256sum -c - >/dev/null
      chmod +x "$tools/buf.tmp"
      mv "$tools/buf.tmp" "$tools/buf"
      ;;
    *)
      GOBIN="$tools" go install "github.com/bufbuild/buf/cmd/buf@v${BUF_VERSION}"
      ;;
  esac
fi
GOBIN="$tools" go install "google.golang.org/protobuf/cmd/protoc-gen-go@${PROTOC_GEN_GO_VERSION}"
GOBIN="$tools" go install "connectrpc.com/connect/cmd/protoc-gen-connect-go@${PROTOC_GEN_CONNECT_GO_VERSION}"

if [ "${1:-}" = "--generate" ]; then
  (cd proto/sensor-v3 && buf generate)
  echo "generated pkg/sensorproto/v3"
  exit 0
fi

echo "== the .proto is the platform's ($UPSTREAM_REF)"
upstream="$(mktemp)"
out="$(mktemp -d)"
trap 'find "$out" -delete; rm -f "$upstream"' EXIT
if curl -fsSL -o "$upstream" "$UPSTREAM"; then
  if ! cmp -s "$upstream" proto/sensor-v3/openctem/sensor/v3/sensor.proto; then
    diff -u "$upstream" proto/sensor-v3/openctem/sensor/v3/sensor.proto || true
    echo "::error::proto/sensor-v3 differs from openctem $UPSTREAM_REF: copy it again and run scripts/check-proto-v3.sh --generate"
    exit 1
  fi
else
  echo "::warning::could not fetch $UPSTREAM; the copy was not compared"
fi

echo "== buf lint"
(cd proto/sensor-v3 && buf lint)

echo "== generated code is current"
sed "s#out: \.\./\.\.#out: $out#" proto/sensor-v3/buf.gen.yaml > "$out/buf.gen.yaml"
(cd proto/sensor-v3 && buf generate --template "$out/buf.gen.yaml")
if ! diff -r "$out/pkg/sensorproto/v3" pkg/sensorproto/v3; then
  echo "::error::pkg/sensorproto/v3 is stale: run scripts/check-proto-v3.sh --generate and commit the result"
  exit 1
fi
echo "proto v3 checks passed"
