package sensorkit

import (
	"fmt"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
)

// Scan traffic through the organization's proxy pools (sensor proxies). A
// scan or retest command may carry the pool its tools' connections go
// through; the sensor's owner keeps a veto here:
//
//	SENSOR_SCAN_EGRESS        platform (default): accept the pools the platform sends
//	                          direct-only: refuse every job that carries a pool
//	                          (refusal egress_refused_by_host); the sensor does not
//	                          report egress.upstream@1, so it gets none
//	SENSOR_SCAN_EGRESS_ALLOW  comma list of host:port (or host, any port) upstream
//	                          proxies this sensor accepts; a job naming another
//	                          endpoint is refused (egress_refused_by_host).
//	                          Empty: any endpoint that passes validation.
//
// Endpoints are validated whatever the list says (no loopback, link-local,
// metadata, multicast, reserved addresses; checked again at every dial).
// A shared sensor never runs a pooled job.
const (
	EnvScanEgress      = "SENSOR_SCAN_EGRESS"
	EnvScanEgressAllow = "SENSOR_SCAN_EGRESS_ALLOW"
)

// SENSOR_SCAN_EGRESS values.
const (
	ScanEgressPlatform   = "platform"
	ScanEgressDirectOnly = "direct-only"
)

// ScanEgress is the sensor-local setting on platform proxy pools.
type ScanEgress struct {
	Mode  string
	Allow upstream.Allow
}

// ResolveScanEgress reads SENSOR_SCAN_EGRESS and SENSOR_SCAN_EGRESS_ALLOW.
// A value it cannot use is an error naming the setting (exit code
// ExitUsage).
func ResolveScanEgress() (ScanEgress, error) {
	s := ScanEgress{Mode: ScanEgressPlatform}
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvScanEgress))); v {
	case "", ScanEgressPlatform:
	case ScanEgressDirectOnly:
		s.Mode = ScanEgressDirectOnly
	default:
		return ScanEgress{}, usageError(fmt.Errorf("%s=%q: use %s or %s", EnvScanEgress, v, ScanEgressPlatform, ScanEgressDirectOnly))
	}
	allow, err := upstream.ParseAllow(os.Getenv(EnvScanEgressAllow))
	if err != nil {
		return ScanEgress{}, usageError(err)
	}
	s.Allow = allow
	return s, nil
}

// AcceptsPools reports whether the setting accepts platform proxy pools.
func (s ScanEgress) AcceptsPools() bool { return s.Mode != ScanEgressDirectOnly }

// policy is the executor's veto (a shared sensor refuses every pool).
func (s ScanEgress) policy(shared bool) core.EgressPolicy {
	switch {
	case shared:
		return core.EgressPolicy{DirectOnly: true, Reason: "a shared sensor runs no job through an organization's proxy pool"}
	case !s.AcceptsPools():
		return core.EgressPolicy{DirectOnly: true}
	}
	return core.EgressPolicy{Allow: s.Allow}
}

// AcceptsEgressPools reports whether this sensor may report
// core.CapabilityEgressUpstream as far as its settings go: not shared and
// SENSOR_SCAN_EGRESS is not direct-only. The sensor reports it only when
// its tool tasks also run confined to the task forwarder (the runtime's
// status, like executor.CapabilityNetConfined).
func (k *Kit) AcceptsEgressPools() bool {
	return !k.s.shared && k.s.scanEgress.AcceptsPools()
}
