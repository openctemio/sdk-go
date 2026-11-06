### Added: every local policy report says whether private targets are admitted

- `LocalPolicyReport.AllowPrivate` (`allow_private`) is sent on every heartbeat and manifest, also when the sensor has no local policy file. It is true only when the host's `SENSOR_ALLOW_PRIVATE_TARGETS=1` switch (and, with a policy, its `targets.allow_private`) admits RFC1918 and IPv6 ULA targets, and false when a required policy is missing. Before, it was reported only inside an enforced policy's summary, so the platform could not see that a default install refuses private targets and dispatched jobs that then failed on the host. No operator action; the platform uses the field to refuse such scans at plan time.
- New `LocalPolicy.AllowsPrivate()` returns the same value.
