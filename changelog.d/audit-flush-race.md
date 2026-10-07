### Fixed: the audit logger no longer loses events when it stops

- `audit.Logger.Stop` waits for the flushes `Log` starts before its final flush and before closing the file. A flush that had taken events from the buffer could write them after the file closed, and they were lost (seen as 996 of 1000 events in `TestLogger_ConcurrentLogging`).
