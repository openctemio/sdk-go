// Package legacyv1 is the only place the SDK still spells the pre-sensor
// "agent" vocabulary (RFC-023 §9.5).
//
// Sensor protocol v1 (the /api/v1/agent/* wire) is retired: the platform
// removed it in 2026-10 and the SDK speaks protocol v2 only. What stays here
// is what existing installations still carry:
//
//   - configuration on disk or in the environment: the AGENT_* environment
//     variables and flags and the ~/.openctem/agent-credentials.json file,
//     each read under its old name only to migrate it (env.go, migrate.go,
//     config.go, and internal/sensorstate for the credentials file);
//   - the sensor-id JSON key of credentials files older SDKs wrote.
//
// Everything else in the SDK uses sensor terms.
//
// Stability: Frozen (docs/STABILITY.md): no additions; removed when the
// configuration it reads is retired.
package legacyv1

// FieldSensorID is the JSON key of the sensor id in credentials files
// written by older SDKs.
const FieldSensorID = "agent_id"
