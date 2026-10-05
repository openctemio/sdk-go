### Documentation

- `docs/rfcs/sensor-sdk-v2.md`: the accepted design for the next SDK
  generation (one tool contract with a `tool.yaml` manifest, out-of-process
  execution for every tool, adapter protocol v1 for any language, one
  runtime, stability tiers, transport v3 behind the SDK). `docs/STABILITY.md`
  now gives every package a tier (Stable, Beta, Frozen, Internal-bound,
  Deprecated). The module description no longer lists scanner wrappers
  (they moved to the sensor in v0.17.0).
