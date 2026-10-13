### Added: per-target and per-task budgets, and per-command progress on the heartbeat

- `ScanCommandPayload.Budget` (`TaskBudget`: `target_seconds`, `task_seconds`,
  `stall_seconds`) carries the platform's layered budget. Every value is
  clamped (a target budget to 1 s – 1 h, a task to 1 min – 24 h).
- `ScanOptions.TargetTimeout` is the per-target budget: a tool wrapper passes
  it as the tool's own per-request or per-host timeout flag.
- `core.RunPerTarget` runs one function per target with that budget, bounded
  concurrency, a reach `timeout` outcome for a target that exceeds it, and the
  finished targets kept when the job's context ends. One unresponsive host
  costs one target budget instead of holding up the whole task.
- Without an explicit `timeout_seconds`, a job's context ends at twice its
  task budget, so a slow but progressing task is not cut at its estimate.
- Every scan job has a `core.Progress` (`core.TargetDone(ctx, target)`); the
  heartbeat reports each held command's finished targets as `progress` to a
  platform that lists the `command_progress` feature, so it can tell a slow
  task from a stuck one.
