### Fixed: a report with one finding above the platform's request limit no longer loops on 413

- A report whose single finding (or asset) is larger than the platform's or a reverse proxy's body limit was re-sent in a tight loop with no back-off: about 1,000 PUTs a second, each also rewriting the outbox progress and logging, until the delivery's context ended. The outbox delivers one item at a time by default, so every later result of the sensor waited behind it.
- The SDK now stops as soon as halving the segment no longer makes the refused request smaller: the push fails with an error that says the report cannot be split below the limit, one log line names the request's size, and the outbox keeps the report as a dead letter.
