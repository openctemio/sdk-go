### Removed: the protocol v1 fallback client

- The client speaks sensor protocol v2 only. Every call that used to fall back
  to `/api/v1/agent/*` when the platform did not offer a v2 feature (results,
  heartbeat incl. `SendHeartbeatWithHints` / `SendHeartbeatForCancels` /
  `TestConnection`, command poll and transitions, `CheckFingerprints`,
  `BaselineDiff`, `GetSuppressions` and its user-route fallback, and
  `platform.PlatformClient.RenewKey`) now answers `client.ErrV2Unsupported`
  (`platform.ErrRenewUnsupported` for renewal) against a platform that does
  not serve the v2 route. The outbox keeps such a report queued instead of
  dead-lettering it.
- Removed with it: `client.ProtocolV1`, `client.IngestResponse`,
  `Client.UploadChunk` / `AsChunkUploader`, the v1 chunk upload in `pkg/chunk`
  (`Splitter`, `Manager`, `Config`, `Uploader` and their types; `SplitSegments`
  stays), `platform.SensorBuilder.WithChunkManager`, `PlatformSensor.ChunkManager`
  / `NeedsChunking` / `SubmitChunkedReport`, the v1 wire constants of
  `pkg/sensorproto/legacyv1` (its settings migration stays),
  `protov2.FeatureResultsV2`, `protov2.HeaderProtocolAdvert`,
  `protov2.DeprecationProtocolV1`, and the v1 routes of the conformance fake
  (`FakePlatform.V1Reports`). Requests no longer carry `X-Agent-ID`: protocol
  v2 identifies a sensor by its key.
- `PlatformSensor.SmartSubmitReport` returns `(string, error)`: every report
  goes through the upload pipeline (large ones as protocol v2 segments).

### Upgrade notes

- The SDK needs an OpenCTEM API that serves sensor protocol v2 (every API
  since 2026-10-02); the API removed protocol v1. Against an older API every
  platform call answers `client.ErrV2Unsupported`: upgrade the API first.
- `SENSOR_PROTOCOL=v1` (or `-protocol v1`, `client.Config.Protocol: "v1"`) is
  refused with `client.ErrProtocolV1Retired`. Remove the setting; `auto` and
  `v2` are the same.
- Code that used the removed `pkg/chunk` manager or `client.UploadChunk` uses
  `Client.PushFindings`, which splits large reports into protocol v2 segments.
