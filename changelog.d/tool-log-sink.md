### Added: tools on a sensor's own tool host ship their logs

- `Kit.ToolLogSink()` returns the command log sink for a `toolhost.Host` the sensor builds itself (`Host.LogSink`). Before this, only the kit's private host shipped tool lines, so a sensor that ran its scanners through its own host sent none.
- The sink may be taken before `Run`, and sends nothing until the kit runs with a platform client.
- Lines are redacted, bounded per command (2,000 lines / 1 MiB), batched and queued ahead of the command's result, as for the kit's own tools. They never block the tool: past the bounds they are dropped and counted.

### Security: credentials in log text are masked

- Every command log line's text is now also masked for credentials a tool prints about its targets:
  - `Authorization`, `Cookie` and `Set-Cookie` header values;
  - `key=value` or `key: value` pairs (JSON-quoted keys included) whose key names a secret (token, api_key, password, secret, session);
  - the user info of URLs.
- This comes on top of the existing masking of the sensor's key, tool secrets and secret-named fields. The platform redacts again.
