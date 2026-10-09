### Security: new sensors fail closed without a local policy

- A sensor that requires a sensor-local policy and has none refuses every job with a network target (URL, host, IP, CIDR, image reference), custom templates and out-of-band callbacks before any tool starts: `refused by local policy: no_local_policy: ...`, with the refusal rule `no_local_policy`. Jobs without network targets (repository and filesystem scans, health checks, collectors, content refresh) keep running, and the kill switch still applies.
- A sensor requires a policy when `SENSOR_REQUIRE_LOCAL_POLICY=true`, or, with the variable unset, when its key-bound identity was paired by this SDK: pairing now writes `"require_local_policy": true` into `identity/identity.json` (`identity.Identity.RequireLocalPolicy`). `core.LocalPolicyOptions.Required`, `LocalPolicy.Required`, `LocalPolicy.WithRequired` and `sensorkit.ResolveRequireLocalPolicy` expose it.
- Without a policy, `LocalPolicy.CheckTarget` now applies the built-in deny list (loopback, link-local and `169.254.169.254`, multicast, unspecified, CGNAT, reserved, private unless the private-range switch) instead of allowing every target, so a retest or tool task that checks its targets directly cannot reach them.

### Added: posture report

- `local_policy.required` (`true`/`false`) on every heartbeat and manifest: `absent` with `required: false` is a legacy install without a policy.
- The manifest member `posture` (sent to a platform that lists the new hello feature `posture`): `platform_tls.pin` (`fingerprint`, `ca_file`, `none`) and `sandbox` (`mode`, `sandboxed`, `network_enforced`). `core.SensorPosture`, `core.CurrentPosture`, `core.PlatformTLSPin`, `BaseSensor.SetPosture`; the kit sets it.
- The config report's `policy.local` check fails with code `required_absent` while a required policy is missing. The new setting `SENSOR_REQUIRE_LOCAL_POLICY` is registered.

### Upgrade notes

- Existing paired sensors and bearer-key sensors are unchanged (legacy, with a start-up warning) until they set `SENSOR_REQUIRE_LOCAL_POLICY=true` or pair again. A sensor paired with this release, or re-paired, refuses network jobs until `/etc/openctem/sensor-policy.yaml` is installed or `SENSOR_ALLOWED_RANGES` is set; `SENSOR_REQUIRE_LOCAL_POLICY=false` keeps the legacy behavior on purpose.
- A legacy sensor without a policy now refuses built-in-denied targets (metadata, loopback, private without the switch) on paths that called `CheckTarget` directly, as the scan executor already did.
