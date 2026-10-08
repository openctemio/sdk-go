### Added: tool.yaml http — the User-Agent, headers, timeout and TLS of a tool's requests

- `http: {user_agent, headers, timeout, tls: {insecure_skip_verify, min_version}}` in `tool.yaml` (`tool.HTTPSpec`, in the JSON Schema).
  - `ctx.HTTP()` applies it; a request's own values still win.
  - Exec tools pass `{{http.user_agent}}`.
  - The descriptor (and so the platform) carries it, and the task's start log line records it (header names only).
- Refused by validation:
  - `Authorization`, `Cookie` and `Proxy-*` headers (credentials come from the credential broker);
  - framing headers;
  - non-printable values;
  - a timeout outside 1s to 10m;
  - `tls.insecure_skip_verify` for a `vendor` network tool.

  A vendor tool's TLS is always verified.
