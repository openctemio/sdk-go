### Added: `transfer` and `transfer/bundle`, chunked signed feed transfer (api RFC-070)

- `transfer.Fetcher` downloads from ordered origins (release URL, mirrors, a local directory):
  - retries with exponential back-off and jitter; Retry-After on 429/5xx, capped (a longer wait moves to the next origin);
  - per-attempt and overall deadlines, a stall guard, and Range resume of a partial download;
  - conditional GET (ETag) for pointers;
  - a circuit breaker per origin; 404 and hash mismatches move to the next origin at once;
  - every request through the SSRF-guarded client by default; file names are one path element.
- `Blob` keeps content-addressed files in `<cache>/blobs`, verified against sha256 and size before they are stored, so chunks shared by two releases are fetched once.
- `bundle.Writer` writes format v2: gzip JSON Lines chunks named by their digest, with content-defined boundaries from record ids, and a signed manifest per snapshot or delta. `bundle.WritePointer` signs the pointer that pins the manifests.
- `bundle.Consumer` verifies the key set, pointer, manifest pin, signature and caps before any chunk. It then applies chunk by chunk, each through the `Applier` in its own transaction, with a durable `Checkpoint`:
  - a crash resumes at the next chunk;
  - an older sequence is refused;
  - a partial bundle is never marked applied;
  - a delta is used only on top of its base.
- `FileCheckpoint` (0600) is included. Prometheus counters are exposed through `Register` on both types.
