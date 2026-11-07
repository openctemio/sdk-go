### Behaviour change: a required sandbox the host cannot give refuses active work, not the process

- `SENSOR_SANDBOX=required` and `SENSOR_SANDBOX_NETWORK=required` on a host
  that cannot give the control (user namespaces off, a runtime profile that
  blocks them, no Landlock) no longer stop the sensor. It stays online,
  reports the classified cause (`runtime.sandbox_network`, for example
  `userns_disabled_host`; `runtime.sandbox_unconfined` = `active_refused`)
  and refuses every tool that contacts its targets (tier T1 and above).
  Passive T0 lookups still run.
- The guarantee is unchanged: no target-contacting tool runs unconfined. The
  executor backend itself refuses such tasks (`executor.ErrActiveRefused`,
  `Status.RequiredUnmet`); only tasks the tool host marks passive
  (`TaskSpec.Passive`) or that have no network run.
- New setting `SENSOR_SANDBOX_REQUIRED_EXIT=1` keeps the old exit at start
  (before pairing). A shared sensor always refuses to start.
- `SENSOR_SANDBOX_NETWORK=required` with `SENSOR_SANDBOX=off` is now refused
  as a settings contradiction.
- New API: `executor.Config.RefuseActiveWhenUnmet`, `executor.ErrActiveRefused`,
  `executor.Status.RequiredUnmet`, `executor.TaskSpec.Passive`,
  `sensorkit.EnvSandboxRequiredExit`.
