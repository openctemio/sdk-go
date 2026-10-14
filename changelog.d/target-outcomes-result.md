### Added: per-target outcomes in the command result

- A completed scan command's result carries `target_outcomes`: one entry per target of the job, in the ctis `outcome` contract (`done`, `failed` with `unreachable` / `timeout` / `tool_error`, `skipped` with `refused` / `excluded`, `unfinished`). The platform settles every target with an outcome and hands out only the unfinished ones again, instead of rerunning the whole task.
- `pkg/sensorkit/toolhost`: a run that delivers (ok or partial) writes the same list into the report's `target_outcomes` property, from each target's settled state and error class, plus the unfinished targets of a run that stopped part-way. A failed or canceled run carries none.
- `pkg/core`: `TargetOutcomes` builds the list from a report (explicit outcomes, `unfinished_targets`, `failed_targets`; any other target of the run is done). Targets a policy refused before the run are `skipped`/`refused`; a target the scan-target policy rewrote (a resolved path) is named by the payload's own value.
- `pkg/testkit`: `Normalize` removes the `target_outcomes` property (the tool host's stamp, absent in-process).
- ctis bumped to the version with the `outcome` package.
