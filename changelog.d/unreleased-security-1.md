### Security

- **Secret masking reveals at most a quarter of a secret** (CTIS spec 4.8
  and 5.2). `core.MaskSecret` showed the first and last 3 characters of any
  secret over 8 characters, which is most of a 9-12 character password. It
  now shows nothing of a secret under 12 characters and at most a quarter of
  a longer one (at most 4 characters at either end), counts runes instead of
  bytes, and uses a fixed-length marker so the masked value no longer gives
  away the length. `MaskAPIKey` and the betterleaks adapter (which showed
  4+4 characters, all but one character of a 9-character secret) follow the
  same rule. `MaskSecretInText` now hides the whole text when the secret is
  not found in it. `core.GenerateSecretFingerprint` hashed the raw secret
  into the fingerprint, so a short secret could be recovered from the
  fingerprint by brute force; it now hashes the masked value.
  **Identity note:** `secret.masked_value`, and secret fingerprints built by
  these helpers, change once for every secret of 9 or more characters.
  OpenCTEM derives a secret finding's identity from `masked_value`, so the
  first scan after the upgrade reports such secrets under new identities.

- **Sensor-local policy** (api RFC-040 §5.7, owner decisions Q3 (a) and
  Q4 (a)). The network owner writes a read-only YAML file at install time
  (`SENSOR_LOCAL_POLICY`, `sensorkit.Options.LocalPolicyPath`, default
  `/etc/openctem/sensor-policy.yaml` when it exists; `apiVersion:
  openctem.io/sensor-policy/v1`): `targets.allow` / `targets.deny` (CIDRs,
  IPs, host names, `*.domain`), `targets.allow_private`, `ports.allow`,
  `tools.allow`, `checks.allow` (command types), `allow_custom_templates`,
  `allow_interactsh`, `rate.max_rps`, `rate.max_job_seconds`,
  `kill_switch` and `kill_switch_file`. Parsing fails closed: unknown keys,
  malformed entries, a second document, an empty or world-writable file, a
  configured path that does not exist, a private range without
  `allow_private`, or an always-blocked range in `targets.allow` stop the
  sensor (exit code 2). The command poller checks every job after it is
  claimed and before any executor or tool sees it
  (`LocalPolicy.AdmitCommand`): host names are resolved and every address
  must pass, so a name resolving to a denied address is refused; a job's
  `ports` setting (RFC-038) must lie inside `ports.allow`; a refused
  job is reported failed with `refused by local policy: <rule>: <detail>`.
  The executor enforces the same rules again (targets through
  `ScanTargetPolicy.Local`, templates, callbacks) and caps the rate and run
  time. The platform's tool policy, payload switches and limits cannot
  widen it. `LocalPolicy.CheckDial` / `DialContext` are the egress hook
  (RFC-034 forwarder, in-process dials): they dial the checked addresses
  only. A kill switch (policy key, or a file named by `kill_switch_file` or
  `SENSOR_KILL_SWITCH_FILE`) stops claiming, stops running jobs (reported
  failed) and makes the heartbeat say `paused by local policy`. Without a
  policy the sensor works as before and reports `local_policy: absent`
  with warnings; custom templates and interactsh stay allowed there until
  a policy sets them (they default to off in any policy).
  `SENSOR_ALLOWED_RANGES` / `SENSOR_ALLOWED_PORTS` are a shorthand policy
  without a file. Heartbeats and the manifest carry `local_policy` (state,
  digest, summary; never the ranges) only to a platform that lists the new
  hello feature `local_policy` (`protov2.FeatureLocalPolicy`). A scan's
  `timeout_seconds` is now capped at `core.MaxScanTimeout` (24h). New:
  `core.LocalPolicy`, `LoadLocalPolicy`, `ParseLocalPolicy`,
  `LocalPolicyOptions`, `LocalPolicyError`, `ErrRefusedByLocalPolicy`,
  `LocalPolicyReport`, `LocalPolicySummary`,
  `CommandPoller.SetLocalPolicy`, `DefaultCommandExecutor.SetLocalPolicy`,
  `BaseSensor.SetLocalPolicy`, `SensorStatus.LocalPolicy`,
  `Manifest.LocalPolicy`, `client.HeartbeatRequest.LocalPolicy`,
  `conformance.FakePlatform.SetLocalPolicy`.

- **v1 results name their command.** The v1 ingest path (the fallback when
  the platform has no protocol v2, `Protocol: v1`, and the outbox's v1
  delivery) now sends `X-OpenCTEM-Command-ID` with the command id from
  `core.WithCommandID` (`legacyv1.HeaderCommandID`). Without it the platform
  treated every v1 report as unsolicited and, under its `quarantine` policy,
  held it for review (api RFC-040 §5.3). When the platform answers
  `404 COMMAND_NOT_FOUND` (the command finished more than its grace period
  ago), the report is sent once more unbound, as the v2 path does. A command
  id that is not visible ASCII or is longer than 128 bytes is never put on
  the header.
