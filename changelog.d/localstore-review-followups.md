### Security: store rollback detection, stale handles after erasure, link-safe workspace removal

- `localstore.Guarded()` marks a record whose rollback is an attack: the store counts its writes in the sealed meta record, and an older copy put back, a replacement by an unguarded file or a deletion behind the store's back reads as `ErrRollback` and is reported through `OnTamper`. The content pack revocation list is guarded. If `meta.rec` is lost, or an older copy of it is restored (a record then carries a boot generation above it), the boot generation restarts above the records', `Stats.BootReset` is set for the heartbeat, and every guarded record reads as `ErrRollback` until it is written again.
- A `Sealer` or `KV` handle made before `Store.EraseTenant` now fails with `ErrTenantErased` instead of silently creating a new key; asking the store for a new handle is the explicit way to start a tenant over.
- `Outbox.DropTenant` now also returns how many of the tenant's items are in flight (kept; call again before erasing the key). **Behaviour change:** the signature is `(dropped, inFlight int, err error)`. The janitor waits for in-flight items before it erases a tenant.
- Removing a workspace no longer resolves any path outside it: the walk, the chmod and the removal use `os.Root`, so a task that swaps a directory for a link while it is being removed cannot make the sensor change or delete anything outside the workspace.
- `contentcache.Cache.SetPinnedKeys` replaces the pinned signing keys and forgets earlier load checks, so a pack signed only by a key no longer pinned stops loading at once.

### Changed: the version 1 outbox key is retired

- With a store, once no version 1 item is left the outbox records that in the store and then deletes the old `outbox.key` (only the default file inside the outbox directory). A fresh outbox with a store no longer creates one. A version 1 item that appears after retirement is quarantined as unreadable.

### Changed: a full outbox refuses new results instead of evicting queued ones

- The byte cap no longer evicts pending reports or command results: it evicts dead letters, then command log batches (best effort by design). When unacknowledged results alone fill the outbox, `Enqueue` returns the new `outbox.ErrFull` without writing (the client then tries to send directly, as for any disk refusal), `Stats.Refused` counts it and a warning is logged at most once a minute. A reserve of 1/50 of the cap is kept for command results, so running commands can still report their end.
- New `Outbox.AcceptsWork`: false while unacknowledged results hold 85 % of the cap or the last refused item would still not fit. `localstore.OutboxCleaner` gains `AcceptsWork`, and `Janitor.AcceptsWork` and `Status.StopClaiming` follow it: results beat new work.
- **Behaviour change:** `MaxAge` (`SENSOR_OUTBOX_MAX_AGE`) now deletes dead letters only; a pending item is kept until the platform acknowledges or refuses it.
- A janitor sweep can no longer remove a workspace that is being created (it is live before its directory exists).
