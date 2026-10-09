### Added: the job HTTP policy carries headers

- A scan job's `http_policy` can now carry `headers` (`core.OrgHTTPPolicy.Headers`). These are headers the platform requires on every request of the job's tools, for example a bug-bounty program's identification header (api RFC-065).
- At most 10 headers. Names must be tokens and values printable ASCII of up to 200 bytes.
- The tool host merges them after the manifest: each replaces a `tool.yaml` header of the same name, whatever its case.
- Refused names:
  - credentials: `Authorization`, `Cookie`, `Proxy-*`;
  - headers the HTTP client and the forwarder own: `Host`, `Content-Length`, `Transfer-Encoding`, `Connection`, and similar.
- A policy that breaks these rules fails the job.
