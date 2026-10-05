// Package chunk splits a large CTIS report into protocol v2 segments
// (api RFC-026 §3.5): SplitSegments returns complete CTIS documents, each with
// the report's tool and metadata and the assets its findings reference, within
// the platform's per-segment limits. The results client (pkg/client) uses it.
//
// The protocol v1 chunk upload (Splitter, Manager) is gone with protocol v1.
//
// Stability: Internal-bound (docs/STABILITY.md): public today because other
// public packages use it; it moves under internal/ before v1.0.0. Do not
// import it from a sensor.
package chunk
