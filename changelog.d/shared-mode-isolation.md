### Security: shared mode, the per-job isolation profile of a sensor that runs jobs of many tenants

- `SENSOR_SHARED_MODE=1` (or `sensorkit.Options.Shared`) requires the tool sandbox and network confinement. A sensor that sets `SENSOR_SANDBOX` or `SENSOR_SANDBOX_NETWORK` to anything weaker, or that runs on a host that cannot give both, refuses to start before it pairs. So does a shared sensor without a loaded local policy.
- `executor.Config.Shared`: a task's write paths and its `HOME`, `TMPDIR`, `TMP`, `TEMP` and `XDG_*` directories must lie beneath the task root, so no writable cache, output or configuration directory is shared between jobs. Every task directory is removed after its task.
- `core.ScanTargetPolicy.Shared` and `toolhost.Host.Shared`: a private target passes only when the operator allows private targets and it lies in the job's zone ranges. Loopback, link-local, metadata and CGNAT addresses never pass. The rule applies at admission and again to every address pinned for the task's forwarder.
- `toolhost.Host.Shared` refuses to run a tool on a backend that does not enforce every sandbox control and confine the network.

### Added: zone rule helpers; capability shared.isolation@1

- `core.WithJobZone`, `core.JobZoneFromContext`, `core.ParseZoneRanges`, `core.CheckSharedAddr` and `core.CheckSharedPrefix` implement a shared job's zone rule. Zone ranges will come only from the job's verified signed statement. An unsigned `zone_ranges` command field is ignored, so until the statement carries ranges, shared jobs reach public addresses only.
- A sensor in shared mode advertises `shared.isolation@1` (`sensorkit.CapabilitySharedIsolation`), based on its runtime state.
- Setting `SENSOR_SHARED_MODE` (`0`, `1`).
