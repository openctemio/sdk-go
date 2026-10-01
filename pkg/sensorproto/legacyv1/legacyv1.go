// Package legacyv1 is the only place the SDK still speaks the pre-sensor
// "agent" vocabulary (RFC-023 §9.5). It mirrors the API's
// pkg/sensorproto/legacyv1.
//
// Two kinds of name keep the old spelling, both because something already
// deployed depends on the exact bytes:
//
//   - Sensor protocol v1, the wire between a sensor and the API: the
//     /api/v1/agent/* routes, the X-Agent-ID header, the "agent_id" and
//     "agent_preference" JSON keys and the "agent" CTIS discovery source.
//     Protocol v1 is frozen (RFC-023 §9.2 C1). It is retired by raising the
//     minimum sensor protocol, never by renaming. Go struct tags cannot refer
//     to constants, so the "agent_id" keys also appear in the tags of the wire
//     types; the golden test in ./goldentest pins every request and response
//     byte for byte.
//   - Configuration an existing installation already has on disk or in its
//     environment: the AGENT_* environment variables and the
//     ~/.openctem/agent-credentials.json file. Each is read under its old name
//     only to migrate it (see env.go, and platform.EnsureRegistered for the
//     credentials file).
//
// Everything else in the SDK uses sensor terms.
package legacyv1

// Protocol v1 routes (tenant sensors). The platform-sensor routes live under
// /api/v1/platform/* and carry no "agent" in their path.
const (
	// PathPrefix is the sensor protocol v1 mount (sensor API-key auth).
	PathPrefix = "/api/v1/agent"

	PathHeartbeat          = PathPrefix + "/heartbeat"
	PathIngest             = PathPrefix + "/ingest"
	PathIngestCheck        = PathPrefix + "/ingest/check"
	PathIngestBaselineDiff = PathPrefix + "/ingest/baseline-diff"
	PathIngestChunk        = PathPrefix + "/ingest/chunk"
	PathCommands           = PathPrefix + "/commands"
	// PathRenew is the sensor's API-key self-renewal (RFC-014).
	PathRenew = PathPrefix + "/renew"
)

// PathCommand returns the v1 route of an action on one command
// (acknowledge, start, complete, fail). id must already be path-escaped.
func PathCommand(id, action string) string {
	return PathCommands + "/" + id + "/" + action
}

// Protocol v1 header and metadata names.
const (
	// HeaderSensorID carries the sensor's id on every v1 request, for the
	// audit trail.
	HeaderSensorID = "X-Agent-ID"
	// GRPCMetadataSensorID is the same for the gRPC transport.
	GRPCMetadataSensorID = "x-agent-id"
)

// Protocol v1 JSON keys and values.
const (
	// FieldSensorID is the JSON key of the sensor id in v1 request and
	// response bodies (registration response, lease info, exposure ingest).
	FieldSensorID = "agent_id"
	// PayloadKeySensorPreference is the job-payload key the API uses for the
	// sensor selection mode (auto | tenant | platform).
	PayloadKeySensorPreference = "agent_preference"
	// DiscoverySourceSensor is the CTIS discovery_source a sensor puts on the
	// assets it discovered itself. The API accepts it and stores "sensor";
	// an API from before the rename knows only this value.
	DiscoverySourceSensor = "agent"
)
