### Deprecated: sensorkit CI runner mode (CIRun)

- `sensorkit.CIRun`, `NewCIRun`, `CIRunConfig`, `CIRunConfigFromEnv`,
  `DetectCIOIDC`, `CIVerdict` and `WriteVerdict` are deprecated. The sensor no
  longer runs in CI (sensor v0.11.0); CI scanning is the `openctem-ci` runner
  (repository openctemio/ci), which also handles aggregate runs and the Azure
  Pipelines, Bitbucket, CircleCI and Jenkins identities. Nothing in the sensor
  calls these identifiers; they are removed in a later minor release.
