### Changed: `http.identity@1` covers the whole identification feature (no `http.identity@2`)

- v0.45.0 introduced `toolhost.CapabilityHTTPIdentityV2` (`http.identity@2`); it is removed before any sensor advertised it.
  A sensor advertises only `http.identity@1` for locked headers and `user_agent_locked`, the sensor-local `http.headers`,
  the query parameter and the reported identity. An older sensor on `@1` ignores the fields it does not know.

### Behaviour change: one local policy schema, `openctem.io/sensor-policy/v1`, holds every key

- The local policy has a single schema, `openctem.io/sensor-policy/v1`, with every key: targets (including `allow: ["*"]`),
  ports, tools, checks, `managed`, `http` (`user_agent`, `allow_insecure_tls`, `headers`), rate and the kill switch. Until 1.0
  it may gain additive, optional keys; a sensor that predates a key refuses the file as an unknown key (fail closed:
  upgrade the sensor). Breaking changes are decided at 1.0.
- `LocalPolicyAPIVersionV2` and `LocalPolicyAPIVersionV3` are removed and `LocalPolicySchemas` is `["v1"]`. A file with any
  other apiVersion (v2, v3 and the v4 of v0.45.0 included) is refused with "policy apiVersion is ...; it must be
  openctem.io/sensor-policy/v1": rewrite the file's apiVersion line, or regenerate it (`sensors.sh set-policy`).
  Upgrade note: files written for the sensors in the field with `v2` or `v3` need that one line changed.

### Upgrade notes: removed exported constants (intended break, v0.45.0 constants that no release used)

- `core.LocalPolicyAPIVersionV2`, `core.LocalPolicyAPIVersionV3` and `toolhost.CapabilityHTTPIdentityV2` are removed. Use
  `core.LocalPolicyAPIVersion` (`openctem.io/sensor-policy/v1`, the only schema) and `toolhost.CapabilityHTTPIdentity`
  (`http.identity@1`). `core.LocalPolicyAPIVersionV4` existed only in v0.45.0 and is removed too.
- A policy file whose apiVersion is `.../v2`, `.../v3` or `.../v4` is now refused: change its apiVersion line to `.../v1`
  (the keys are unchanged) or regenerate it with `sensors.sh set-policy`.
