### Fixed: The local policy never raises a tool's default rate, and kit-based sensors apply http.headers
- When a job sets no rate, the tool runs at the lower of its own default and the policy's `rate.max_rps` (it was set to the maximum, which can be faster than the tool's default).
- `pkg/sensorkit` passes the local policy's `http.headers` to the tool host; they were ignored for kit-based sensors.
