### Added: run a legacy scanner or collector as a tool of the tool contract

- `pkg/tool/toolcompat` (Beta, transitional): `FromScanner(manifest, scanner,
  ...)` and `FromCollector(manifest, collector, ...)` turn a `core.Scanner`
  or `core.Collector` into a `tool.Tool`. Compiled into the sensor and
  listed in `adapter.Dispatch`, it runs out of process in the task sandbox
  like any tool: the child scans (all targets at once for a
  `core.MultiTargetScanner`), converts the raw output with the SDK's
  parsers (or `WithParser`), and emits the report through the runtime's
  checks, so an undeclared record type is quarantined and a failed scan
  fails only its target.
- `WithState` sends the scanner's exported fields to the child (fields
  tagged `json:"-"` stay behind); secrets travel only as declared
  credentials (`WithPrepare` with `ctx.Secret`, or
  `WithAPIKeyCredential` for a collector, whose `APIKey` is never sent).
  The task's configuration, validated against the manifest's schema,
  reaches the scanner as `ScanOptions.Settings`.
