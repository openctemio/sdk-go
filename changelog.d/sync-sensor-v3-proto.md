### Changed: sensor v3 proto synced with the platform

- `proto/sensor-v3` is copied again from the platform. The only change is the documented `content_type` of an ingest chunk (`application/vnd.ctis+json; version=2.0`, CTIS 2.0); fields, numbers and types are unchanged, so the wire format is the same.
