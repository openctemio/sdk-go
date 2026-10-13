### Added: `net.confined@1` capability and a network-confinement setup check

- `executor.CapabilityNetConfined` (`net.confined@1`) names the capability a sensor advertises when every tool it runs for a job is network-confined to the task's forwarder. The platform sends jobs that need confinement (a web scope, scope limits) only to a sensor that advertises it. A sensor advertises it from its runtime's status (`Status().NetworkEnforced` with tools out of process), never from a setting.
- The config report has a new check, `runtime.sandbox_network`: `confined` (pass), or a warning with the detected cause: `userns_blocked` (the container runtime's seccomp profile refuses user namespaces: run with the sensor's seccomp profile), `userns_restricted` (the host restricts unprivileged user namespaces: keep the default AppArmor profile), `off` (`SENSOR_SANDBOX_NETWORK=off`), `sandbox_off` (`SENSOR_SANDBOX=off`) or `unavailable`. The platform's setup checklist explains each code and its fix.

### Fixed: versioned sensor-wide capabilities are reported

- The tool registry dropped any capability with `@` in its name, so `scope.limits@1` (since sdk-go v0.18) and `net.confined@1` never reached the platform: a confined sensor was never given the jobs that need confinement or scope limits. Capability names may now contain `@`.
