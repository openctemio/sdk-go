// Package tool is the one contract for every workload a sensor runs: a
// target scanner, a connector to a vendor API, a parser of a file or an
// enricher of findings.
//
// Stability: Stable (docs/STABILITY.md).
//
// A tool is a manifest plus a run function:
//
//   - the Manifest (a tool.yaml file, apiVersion openctem.io/tool/v1)
//     declares what the tool is: its execution class, its intrusiveness
//     tier, the CTIS types it consumes and produces, a typed configuration
//     schema, the permissions it needs (network, filesystem, credentials),
//     its resources and its self-test fixtures;
//   - Run(ctx, task) does the work and reports through ctx: records through
//     an Emitter that checks each one as it is emitted, progress, logs,
//     artifacts and the outcome of each target, and returns a categorized
//     Error when it fails.
//
// The runtime (pkg/sensorkit) never calls Run in its own process. A Go tool
// compiled into a sensor runs in a separate, sandboxed process (the sensor
// re-executes itself), speaking the same adapter protocol a tool in any
// other language speaks (pkg/tool/adapter). Only pkg/testkit calls Run
// in-process, applying the same rules the runtime applies, so a tool that
// would be stopped in production fails its unit test.
//
// The runtime owns every guarantee: it admits targets against the policy,
// validates the configuration against the manifest's schema, delivers only
// the credentials the manifest declares, checks every record again on its
// side of the process boundary (CTIS validity, declared output types,
// size and count limits, control characters) and stamps the provenance.
// Nothing in this package lets tool code skip any of it.
//
// The design is docs/rfcs/sensor-sdk-v2.md.
package tool
