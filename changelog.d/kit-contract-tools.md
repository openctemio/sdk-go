### Added: the kit runs tools of the tool contract (AddTool, adapter directories)

- `Kit.AddTool(t)`: a tool compiled into the sensor (or a legacy scanner
  through `toolcompat.FromScanner`) is reported with its contract and runs
  dispatched and scheduled scans out of process: each task admitted
  against the local policy in force (reloads included), only declared
  credentials delivered (`Options.ToolCredentials`), output checked and
  stamped, then delivered through the outbox like any scan. The program
  calls `adapter.Dispatch(tools...)` at the top of `main`.
- `Options.AdapterDirs` / `SENSOR_ADAPTER_DIRS`: tools the operator
  installed as `tool.yaml` plus a program (adapter protocol v1 or the exec
  profile), in `<dir>/tool.yaml` or `<dir>/<name>/tool.yaml`. A manifest is
  loaded only when the directory, the manifest and a program shipped next
  to it are owned by root or the sensor's user, not group- or
  world-writable and not symbolic links, and only with a run section; a
  name the sensor already provides is never replaced. A refused manifest is
  a warning and an `adapter_refused` check in the config report.
- `toolcompat.AsScanner` serves a contract tool to the command executor; a
  task none of whose targets was scanned fails its command instead of
  completing with no results.
- `core.ToolSettings.Values()`; `conformance.FakePlatform.AcceptedReports()`.
