### Behaviour change: a refused scan target no longer fails the whole job

- A scan job target that the sensor-local policy refuses, or cannot check, is removed from the job, and the job runs on the other targets. "Cannot check" means the name does not resolve or the target is a wildcard pattern. The same applies to the executor's own check before the scanner starts.
- The command completes with `metadata.refused_targets` (`{target, reason, rule, detail}`, at most 100), `metadata.refused_targets_total` and `metadata.partial: true`. Reasons: `unresolvable`, `wildcard_pattern`, `denied_by_policy`, `invalid_target`.
- The command still fails when every target is refused, or when the single target of a single-target job is refused. The error lists the targets.
- Retest and validation commands still refuse the whole job when one target is refused.
- An address the policy cannot check is still never scanned. A refused target never reaches an executor or a tool.

### Added: per-target admission and the poller's lines in the command log

- `LocalPolicy.AdmitCommandTargets` returns a `CommandAdmission` with the refused targets. It also rewrites the payload of a scan job. `AdmitCommand` keeps refusing the whole job.
- Added `core.RefusedTarget`, the `RefusedTarget*` reasons, the `Meta*` keys and `RefusedTargetsMetadata`.
- `CommandPoller.SetCommandLogSink` (`core.CommandLogSink`) writes the poller's own lines to the command's log, tagged `source: sensor`. They cover: received, the policy check with each refused target and its reason, a refusal before running, the tool gate, the outcome (completed, partial, failed, timed out, kill switch) and a hand-back (no free slot, busy hosts, drain).
- `sensorkit` wires its log shipper as that sink, so a command refused before any tool started still has a log saying why. Its lines are queued ahead of its result. A hand-back line is sent directly before the release.
- The log shipper continues a command's batch sequence across finishes. The platform keeps the first batch of each number, so a restarted sequence was dropped.

### Changed

- `ScanTargetPolicy` resolves host names with the local policy's resolver when it has a local policy and no `LookupIP` of its own.
