### Security: a per-host request cap in the job's web scope, enforced by the forwarder

- `webscope.Scope` gains `MaxRequestsPerHost` (`max_requests_per_host`, 0 to 1,000,000; 0 is no cap). A confined task's forwarder counts every request it lets through to a host name (any port, scheme or connection; a followed redirect included) and refuses the ones past the cap with the same 403 as a request outside the scope; nothing the task does resets the count. `tool.Context.HTTP` fails such a request before sending it. Path discovery jobs carry the cap with `methods: ["GET", "HEAD"]`, so the forwarder also refuses any other method.
- `pkg/webscope` reads paths with contract `webpath` (`CleanPath`, `Denied`, `Under`), the reading the platform plans with; behaviour is unchanged.
- The forwarder classifies a guarded connection's answers with contract `edgeprotect` from the start of the body that arrived with the headers too (never waiting for more), so a challenge page that shows only in its body is a block from the first answer. A vendor's rate-limit page under another status than 429 or 503 slows the host like a 429.
- `wordlist.Normalize` drops entries that name a state-changing action (contract `webpath.Destructive`: logout, delete, reset, ...) for the `web-paths`, `web-files`, `api-routes` and `params` purposes, when a list is built and when a task's list is composed.

### Changed

- Requires `github.com/openctemio/contract` with package `webpath` (pinned to the commit that adds it until its release).
