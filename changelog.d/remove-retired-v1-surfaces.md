### Removed: protocol v1 gRPC transport, v1 proto files and the threat-intel client calls

- `pkg/transport/grpc` and `proto/openctemio/v1` (with their buf configuration) are removed, as announced when they were deprecated: no platform serves them. `google.golang.org/grpc` is no longer a direct dependency. Sensor protocol v3 (`pkg/sensorproto/v3`) is unchanged.
- `Client.GetEPSSScores`, `Client.GetKEVEntries` and `Client.EnrichFindings` (and the `EPSSScore` and `KEVEntry` types) are removed: they called `/api/v1/threatintel/epss` and `/api/v1/threatintel/kev`, which the platform does not serve, so every call failed. The platform enriches findings with EPSS and KEV itself on ingest.
- `legacyv1.HeaderSensorID` and `legacyv1.GRPCMetadataSensorID` are removed: no route reads them. `legacyv1.FieldSensorID` stays for migrating old credentials files.

### Upgrade notes

- Drop any import of `pkg/transport/grpc` and any call to `Client.GetEPSSScores`, `Client.GetKEVEntries` or `Client.EnrichFindings`; nothing replaces them on the sensor side (the platform enriches findings on ingest).
