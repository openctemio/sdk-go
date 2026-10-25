### Changed: plain local policy messages

- A sensor that needs a local policy and has none logs one short line: network scans are refused until one is added, copy the policy the console suggests to `/etc/openctem/sensor-policy.yaml` and reload with SIGHUP, or set `SENSOR_ALLOWED_RANGES`. The same help ends every `no_local_policy` refusal.
- A private range in `SENSOR_ALLOWED_RANGES` without the private switch now says to also set `SENSOR_ALLOW_PRIVATE_TARGETS=1`; it no longer points at `targets.allow_private`, a key of the policy file the shorthand does not use.
