### Fixed: a stored report states the lease epoch it was made under

- A command-bound report kept in the outbox now records the lease epoch its
  command was held under when the report was stored (`outbox.Meta.LeaseEpoch`),
  and every PUT and commit of the report states that epoch
  (`X-OpenCTEM-Lease-Epoch`), never the one held at delivery. Before, a report
  delivered after a restart stated no epoch, so a platform that had handed the
  run out again bound the late results to the new run.
- Command-bound result requests that state an epoch also name the
  `results_lease_epoch` feature in `X-OpenCTEM-Sensor-Features`: the platform
  then refuses such a request without an epoch.
- `V2PushOptions.LeaseEpoch` sets the epoch a pushed report states (0: the
  one held now).
- Protocol v3: `PutResult` and `CommitResult` carry `lease_epoch` (the proto
  copy follows the platform's); the client fills it from the request.
- The conformance fake enforces the same rules as the platform.
