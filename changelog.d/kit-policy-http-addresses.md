### Fixed: sensorkit sensors apply the local policy's http section and pin confined tasks to admitted addresses

- **The problem.** The kit's tool host reads optional policies by type assertion, and the kit's policy implemented neither of two of them:
  - without `HTTPPolicy`, schema v3 `http.user_agent` and `http.allow_insecure_tls` were ignored for kit-hosted tools;
  - without `HostResolver`, a confined task's forwarder resolved a target host again at start instead of dialing the addresses the policy admitted.
- **The fix.** The kit's policy implements both now, and compile-time assertions keep every optional policy implemented.
- The local policy report now shows the http section (`http_user_agent`, `allow_insecure_tls`).
