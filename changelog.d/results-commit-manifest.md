### Added: commit manifest and resume from held segments

- `PushResultsV2` sends the commit manifest of a segmented report to a platform that lists `results_manifest` on hello: each segment's SHA-256 over its bytes before Content-Encoding, its size and its asset and finding counts, the totals and the report hash (`protov2.ReportRoot`: SHA-256 over the segment hashes in order). The platform compares every value with what it received; a report it cannot verify is not used to close findings by absence. Older platforms get the plain commit.
- A push resumed from `V2Progress` (the outbox's next delivery after a restart) asks the platform which segments of the report it already holds (`segments.held` on the status) and does not send those again.
- `protov2`: `CommitRequest.Segments/Totals/ReportSHA256`, `SegmentManifest`, `SegmentCounts.Held`, `Status.Integrity`, `FeatureResultsManifest`, `ReportRoot`. The conformance fake verifies the manifest when `SetResultsManifest(true)`.
