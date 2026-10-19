### Added: sensorkit wires the local store, job recovery and the janitor

- A daemon opens `localstore` beside its outbox (`SENSOR_STORE_DIR`, `SENSOR_STORE_KEY_FILE`, `SENSOR_WORKSPACE_DIR`; defaults next to the outbox directory) and hands it to the outbox: new items are sealed per organization (file format 2). Existing items are read as before and the outbox key becomes the organization sensor's data key; a fresh outbox no longer creates `outbox.key`.
- At start the kit reports every job the journal shows unfinished as a failed command result (`Client.ReportInterruptedCommand`), sweeps the workspaces a crash left, and starts the janitor (at start, after acknowledgement bursts, every 10 minutes). `Kit.SetStorePolicy` sets its policy, clamped; the platform has no policy field for it yet, so the defaults apply.
- `core.CommandPoller.SetClaimGate`: the poller claims nothing while the outbox is full of unacknowledged results, storage is at the high watermark or the volume is low, and resumes when that clears; each change is logged once.
- The heartbeat carries `local_store` (`core.LocalStoreReport`: bytes per class, watermark, stop-claiming, last sweep, boot generation and reset) only to a platform that lists the new `local_store` feature (`protov2.FeatureLocalStore`). `client.OutboxConfig.OnDelivered` is new.
- `doctor` checks `storage.store_dir`, `storage.store_key`, `storage.store_disk` and `storage.store_persistent` (the store holds the keys of the sealed outbox items: keep it on the same persistent volume as the outbox).
- The store directory and its key are in the tool sandbox's protected paths.
- `pkg/sensorproto/relay` is checked against the platform's cross-implementation batch framing vector (`testdata/vector-batch-v1.json`).
