### Added: an encrypted, crash-safe local store for sensors (`pkg/localstore`)

- One master key, read from a mounted secret (`Options.KeyFile`) or created next to the data, wraps a random data key per tenant. A shared sensor keeps each organization's records under its own key; `EraseTenant` deletes the wrapped key first, so a copy of the records left on a snapshot or a backup can no longer be decrypted.
- Records are sealed with AES-256-GCM and bound to their tenant, namespace and name; a record that is edited, truncated or copied over another one is quarantined, counted and reported (`OnTamper`), never returned and never a crash. Writes are atomic (temporary file, fsync, rename, fsync of the directory); a kill -9 at any point leaves the previous or the new record.
- Records may carry an expiry: once it passes, `Get` returns `ErrExpired` and no data, so scope-bearing data cached for offline work fails closed.
- `Disk` and `AcceptsWork` report the volume's free space and inodes: below the low mark a sensor stops taking new work; below the critical mark only writes marked `Critical` and deletions go through.
- A boot generation, kept in a sealed record and incremented by every start, lets the platform notice an old copy of the store being restored.
- `Sealer` gives the outbox and the content cache the same per-tenant sealing for the files they keep themselves.
