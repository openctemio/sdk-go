### Added: the sensor owner's headers, the job's query parameter and a report of what was sent

- Local policy schema `openctem.io/sensor-policy/v4` adds `http.headers`: up to four `{name, value}` identification headers
  that the sensor sends on every request of every task that sends HTTP to its targets, whichever organization's job it is.
  They obey the rules of every identification header (token name, printable ASCII value of at most 200 characters, never a
  credential, connection or `Proxy-*` header). A v3 file with `headers` is still refused.
- A job's `http_policy` can lock names (`locked_headers`, `user_agent_locked`). The sensor's headers replace an unlocked job
  header of the same name, never a locked one; the User-Agent follows the same rule. The merged set is capped at 16 headers
  (the job's own cap stays 10) and a task over it is refused with a message naming the cap.
- A job's `http_policy.query` (`{name, value}`) is added to every request URL by tools that declare `features.http_query`
  (`ctx.HTTP()` does it) or pass `{{http.query:-flag}}`. Any other tool runs, and the result reports the parameter as not applied.
- The result's metadata `http_identity` reports the identification actually sent per tool (headers with source, secret-looking
  values masked, anything not applied with its reason). New capability constant `toolhost.CapabilityHTTPIdentityV2`
  (`http.identity@2`).
- **Behaviour change:** a sensor whose owner sets `http.headers` refuses a networked tool that cannot carry headers, the same
  rule as for a job's identification.
