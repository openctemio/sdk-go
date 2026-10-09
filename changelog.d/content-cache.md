### Added: `sensorkit/contentcache`, the sensor's content pack cache (api RFC-061 K3)

- Packs are addressed by digest.
- **Before a pack is stored:**
  - the downloaded bytes must hash to the digest;
  - the platform's DSSE statement must verify against an operator-pinned key: the tenant content key, naming this sensor's organization, or the platform content key;
  - the statement must name the same digest;
  - the archive must pass the canonical rules again (regular files only, clean relative paths, caps).
- Packs are unpacked read-only under `<root>/packs/sha256-<hex>/`, and the root is private (0700).
- **Using packs:**
  - `Acquire`/`Release` hold a pack per task;
  - `Resolve` sets a task's pack paths from the cache and replaces any path a job sent.
- `Sync` installs the desired set (two downloads at a time) and purges revoked digests, refusing them from then on. It drops least recently used packs outside the desired set while the cache is over its budget; a pack in use is never removed.
- `testdata/platform-vector.json` pins the platform's archive, statement and envelope format.
