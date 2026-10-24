### Added: content manifest `required_features`

- `ContentManifest.RequiredFeatures` (`required_features`, optional, `version` stays 1): behavior a reader must understand to run the task. `ParseManifest`, `Validate` and `Cache.Ensure` refuse a manifest that lists a feature missing from `contentcache.KnownFeatures` (empty in this release) with the new `ErrUnsupported`; the task fails with reason `content_unsupported`, not `content_unavailable`, because requeueing to the same sensor cannot help. Unknown fields are still ignored, so later optional fields never break an older reader.
