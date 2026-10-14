### Added: content delivery from the platform with delta installs (contentcache, client)

- `contentcache.HTTPFetcher` gets content from the platform's sensor content routes (`/api/v2/sensor/content`): the desired-state document, packs by digest, a pack's file index, and files by sha256. `Client.ContentFetcher()` builds one on the sensor's connection and credentials.
- **Delta installs.** When the fetcher serves indexes, a new version of a pack is built from the files the cache already holds plus the changed files it fetches. The rebuilt canonical archive must match the signed digest and size, so integrity is the same as a full download, and any mismatch falls back to the full archive. Each held pack records its file index (`.openctem-index.json`); an archive may not contain that name.
- **Conditional desired state.** `HTTPFetcher.Desired` sends the last `ETag`. A 304 costs no body and reuses the last document.
- **Prefetch.** `Cache.Prefetch` syncs the desired set on a jittered schedule (±20%, with a random first run) and at once on a wake-up, so scans find their content already held.
- **Stats.** `Cache.Stats()` reports hits (held, nothing fetched), misses, delta installs, bytes downloaded and bytes saved.
