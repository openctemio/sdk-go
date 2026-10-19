### Changed: the outbox spreads its drain after the platform comes back

- `Outbox.Wake` (called when a heartbeat is accepted again) no longer starts delivering the whole backlog at once. The drain starts after one random delay of up to `min(WakeSpread, waiting items × 100 ms)`, 30 s at most by default, so a fleet that comes back after a platform outage does not send every queued result in the same second. The queue keeps its order. `outbox.Config.WakeSpread` sets the bound; a negative value drains at once.
