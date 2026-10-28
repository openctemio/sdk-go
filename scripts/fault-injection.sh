#!/usr/bin/env bash
# Fault-injection tests of the host pressure governor and the per-task
# cgroup envelope (research/318), each in a throwaway container:
#   - a CPU hog and memory pressure under a CPU quota and a memory limit;
#   - per-task cgroups in a container whose cgroup is writable.
# The host's Docker socket is never mounted; containers are removed on exit.
set -euo pipefail
cd "$(dirname "$0")/.."
prefix="${FI_PREFIX:-sdk-fault-injection}-$$"
image="${FI_IMAGE:-ubuntu:24.04}"
out="$(mktemp -d)"
cleanup() {
	docker rm -f "$prefix-load" "$prefix-cgroup" >/dev/null 2>&1 || true
	rm -rf "$out"
}
trap cleanup EXIT
GOWORK=off CGO_ENABLED=0 go test -c -o "$out/resource.test" ./pkg/resource
GOWORK=off CGO_ENABLED=0 go test -c -o "$out/executor.test" ./pkg/sensorkit/executor
docker run --rm --name "$prefix-load" --network none --cpus 1 --memory 256m --memory-swap 256m \
	-e OPENCTEM_FAULT_INJECTION=1 -v "$out:/t:ro" "$image" /t/resource.test -test.run 'FaultInjection' -test.v
docker run --rm --name "$prefix-cgroup" --network none --privileged --cgroupns private \
	-e OPENCTEM_CGROUP_ENVELOPE_TEST=1 -v "$out:/t:ro" "$image" /t/executor.test -test.run 'CgroupEnvelope' -test.v
