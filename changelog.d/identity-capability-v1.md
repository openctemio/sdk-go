### Changed: `http.identity@1` covers the whole identification feature (no `http.identity@2`)

- v0.45.0 introduced `toolhost.CapabilityHTTPIdentityV2` (`http.identity@2`); it is removed before any sensor advertised it.
  A sensor advertises only `http.identity@1` for locked headers and `user_agent_locked`, the sensor-local `http.headers`,
  the query parameter and the reported identity. An older sensor on `@1` ignores the fields it does not know.

### Changed: `http.headers` is part of local policy schema v3 (there is no v4)

- v0.45.0 introduced schema `openctem.io/sensor-policy/v4` for `http.headers`; it is removed (`LocalPolicyAPIVersionV4` and
  "v4" in `LocalPolicySchemas`). `http.headers` is an additive, optional key of v3. v1 and v2 stay frozen. A sensor that
  predates the key refuses the file as it would refuse an unknown apiVersion: upgrade the sensor first. A new schema
  version is for breaking changes only.
