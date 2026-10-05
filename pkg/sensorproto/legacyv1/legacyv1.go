// Package legacyv1 is the only place the SDK still spells the pre-sensor
// "agent" vocabulary (RFC-023 §9.5).
//
// Sensor protocol v1 (the /api/v1/agent/* wire) is retired: the platform
// removed it in 2026-10 and the SDK speaks protocol v2 only. What stays here
// is what existing installations and the platform-sensor routes still carry:
//
//   - configuration on disk or in the environment: the AGENT_* environment
//     variables and flags and the ~/.openctem/agent-credentials.json file,
//     each read under its old name only to migrate it (env.go, migrate.go,
//     config.go, and platform.EnsureRegistered for the credentials file);
//   - the sensor-id header and JSON key the platform-sensor routes
//     (/api/v1/platform/*) and the gRPC transport still use.
//
// Everything else in the SDK uses sensor terms.
//
// Stability: Frozen (docs/STABILITY.md): no additions; removed when the
// configuration and routes it serves are retired.
package legacyv1

// Header and metadata names of the platform-sensor routes and the gRPC
// transport.
const (
	// HeaderSensorID carries the sensor id on platform-sensor requests.
	HeaderSensorID = "X-Agent-ID"
	// GRPCMetadataSensorID is the same for the gRPC transport.
	GRPCMetadataSensorID = "x-agent-id"
)

// FieldSensorID is the JSON key of the sensor id in the platform-sensor
// registration response and lease info, and in credentials files written by
// older SDKs.
const FieldSensorID = "agent_id"
