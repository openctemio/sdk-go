### Added: sensors run the platform's retest command

- `sensorkit` serves the `retest` command for every tool whose manifest declares retest (`tool.WithRetest`) and reports capability `retest:<tool>` for each, which the platform routes retests by. The command (`{"scanner", "targets": [addresses], "items": [{ref, target, kind, rule_id, fingerprint}], "timeout_seconds"}`) becomes one retest task that runs out of process like a scan, and the command completes with `metadata.retest.verdicts`: one `still_present`, `fixed` or `unverifiable` per item.
- The command is admitted like a scan before anything runs: the platform's tool policy, the local policy's `checks.allow`, `tools.allow` and every target. An item on an address that is not one of the command's targets, or a tool without retest, fails the command. Timeout: 2 minutes by default, at most 30.
- `toolcompat.Retester` (implemented by the contract tools the kit adds) and `toolcompat.RetestCapability` expose the same to a sensor that wires its own executor.

### Upgrade notes

- A local policy that lists `checks.allow` must add `retest` for the sensor to accept retests; without it the platform's retest of a finding fails on that sensor and settles as unknown.
