### Security: tool tasks are admitted against the sensor-local policy before they start

- `toolhost.Admit` and `toolhost.Host.Policy` (`*core.LocalPolicy` implements
  `toolhost.Policy`): every task of a tool on the tool contract is checked
  before any task directory, credential or process exists. The local
  policy's `tools.allow` and kill switch apply; each target of a tool whose
  network is `targets` passes the target guard (allow/deny lists, private
  ranges, ports, resolved addresses). A refused target is removed from the
  task and reported `skipped` with class `refused_by_policy`, so the tool
  never receives it; a task with no target left is refused. The policy's
  `rate.max_job_seconds` caps the run time. A manifest that declares
  `linux_caps` is refused (the runtime grants none), and `RunOptions.Mode`
  checks the manifest's `modes`.
