### Removed: packages deprecated since v0.18.0

- `pkg/pipeline`, `pkg/audit`, `pkg/credentials`, `pkg/errors`, `pkg/health`, `pkg/metrics`, `pkg/options`, `pkg/enrichers/{epss,kev}`, `pkg/connectors` (with `pkg/connectors/github`) and `pkg/providers/github` are removed, with the `custom-connector` and `custom-provider` examples. They were deprecated in v0.18.0 with removal announced; nothing in the sensor, the asset collector, the Tenable.sc connector, the CI runner or the platform imports them.

### Upgrade notes

- Replace each removed package as docs/STABILITY.md listed it: the outbox through `sensorkit` (pipeline, audit); secrets declared in the tool contract (credentials); categorized tool errors in the tool contract (errors); preflight checks, the config report and the settings registry in `sensorkit` (health, metrics, options); the platform's own EPSS and KEV enrichment (enrichers); the platform's connectors module (connectors, providers).
