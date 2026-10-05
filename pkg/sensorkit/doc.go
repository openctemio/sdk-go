// Package sensorkit is everything a sensor needs to work with the OpenCTEM
// platform, in one call: a sensor implements its tools, the kit runs the
// rest.
//
//	kit, err := sensorkit.New(sensorkit.Options{Name: "my-sensor", Version: version})
//	sensorkit.Exit(err)
//	kit.AddScanner(myScanner)                    // reported, dispatched, scheduled
//	kit.HandleCommand("my_command", myExecutor)  // optional
//	sensorkit.Exit(kit.Run(context.Background())) // blocks; SIGINT/SIGTERM drain
//
// New reads the standard settings (API_URL, API_KEY, SENSOR_ID, SENSOR_NAME,
// SENSOR_PROTOCOL, SENSOR_MAX_JOBS, SENSOR_TOOLS, SENSOR_DRAIN_GRACE,
// SENSOR_SCANNER_PRIORITY, SENSOR_PROTECT_FROM_OOM, SENSOR_OUTBOX*,
// SENSOR_STATE_DIR, SENSOR_CA_CERT_FILE,
// PLATFORM_KEY_AUTORENEW, SENSOR_CONTROL_PROXY, SENSOR_CONTENT_PROXY,
// SENSOR_SCAN_PROXY, HTTP(S)_PROXY / NO_PROXY; the pre-rename AGENT_* names with a
// deprecation warning), refuses settings it would misread with a clear
// message and exit code (ExitCode), and connects the platform client
// (protocol v2 negotiated on hello, v1 for what the platform does not offer;
// SSRF-guarded HTTP, pkg/httpsec) with its durable outbox. Every setting is
// also an Options field, which wins over the environment.
//
// Run reports the tools on every heartbeat (the platform dispatches by that
// report; nobody declares a sensor's tools on the platform), waits while the
// platform rejects the key, heartbeats with the doorbell, renews the API key
// when asked, claims commands into dynamically sized slots (CPU, memory and
// each tool's learned cost, capped by SENSOR_MAX_JOBS), pushes results
// through the outbox, and on SIGINT/SIGTERM drains: nothing new is claimed,
// running commands get the drain grace and are then handed back to the
// platform.
//
// A sensor plugs its own parts in through Options (Content for managed
// scanner content, ScanTargetPolicy, AssetResolver, UnavailableReason),
// AddParser, HandleCommand and UseCommandMiddleware. pkg/core stays
// available for anything the kit does not cover (Kit.Sensor, Kit.Tools,
// Kit.Client).
//
// Stability: Stable (docs/STABILITY.md); runner mode (CIRun, Kit.RunOnce) is
// Beta.
package sensorkit
