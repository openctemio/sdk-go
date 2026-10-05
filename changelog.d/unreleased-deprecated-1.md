### Deprecated

- Packages with no importer in the sensor, the platform or the asset
  collector are marked `Deprecated:` and will be removed in a later minor
  release: `pkg/transport/grpc` and `proto/openctemio/v1` (removed in the
  next minor, which drops the `google.golang.org/grpc` dependency),
  `pkg/adapters/...`, `pkg/pipeline`, `pkg/audit`, `pkg/credentials`,
  `pkg/errors`, `pkg/health`, `pkg/metrics`, `pkg/options`,
  `pkg/enrichers/{epss,kev}`, `pkg/connectors/...`, `pkg/providers/github`
  and `pkg/scanners/tenable`. `docs/STABILITY.md` lists the replacement of
  each.
