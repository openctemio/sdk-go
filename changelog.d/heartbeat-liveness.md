### Added: liveness counters in the heartbeat's command progress

- `core.CommandProgress` carries `records`, `output_bytes` and `cpu_ms` next to `done`/`total`/`finished`: the records the tool host accepted for the job and their bytes, and the CPU time of the job's tool processes with the processes they start (read from `/proc` on Linux; 0 elsewhere). All are monotonic for the job and left out while zero.
- `pkg/sensorkit/toolhost` counts each accepted record (`core.RecordOutput`) and tracks the tool process (`core.TrackProcess`); `core.ExecuteScanner` / `StreamScanner` track the scanner process.
- The platform calls a task stalled only when none of these and the settled targets moved for its stall window, so a slow but working batch tool is not taken back. The counters are hints: they can delay a stall decision, never a task's overrun or a run's cap.
