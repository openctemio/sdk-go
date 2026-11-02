### Fixed: feed relay routes use the plural collection

- The feed relay client calls `/api/v2/sensor/feed-relay-rounds/...` (was `/feed-relay/...`), matching the platform's route naming. The relay shipped in no release yet.
