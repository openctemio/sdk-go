### Added: per-endpoint echo tokens and idle probes in proxy tests

- A `proxy_test` command may carry one echo URL per endpoint
  (`echo.endpoints`), each with a token that names that endpoint alone, so the
  platform can bind every observed exit address to its endpoint. A URL off the
  pool's echo host and port fails that endpoint's test before any connection.
- `probe: true` marks an idle probe of endpoints on probation or in
  quarantine: only endpoints with their own echo URL are probed, each at most
  once per 10 minutes per sensor (`upstream.ProbeGate`); the others are left
  out of the result. New: `upstream.TestSpec.EndpointURLs` and
  `TestSpec.Endpoints`.
