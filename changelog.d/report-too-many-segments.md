### Fixed: a report that needs more segments than the platform accepts says why

- `pkg/client`: a report that needed more segments than the platform's `max_segments_per_report` was given up with no log line. Both 413 give-ups (a request that splitting does not make smaller, and a report that cannot fit the segment count) now log the reason and end the same way: the outbox keeps the report as a dead letter instead of retrying it.
