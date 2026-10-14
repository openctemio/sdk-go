### Fixed: `openctem tool init` marks the standard params scan-scoped

- The `tool.yaml` that `openctem tool init` writes declares each of the capability's standard params (for example `ports`, `top_n`, `rate` of `scan.ports@1`) with `x-octm-scope: scan`. Without it they defaulted to the sensor scope, so a scan that set one of them was refused ("may be set only in the sensor's settings, not by a scan").
- Migration: a tool scaffolded with an earlier release adds `"x-octm-scope": "scan"` to each standard param in its `config` schema.
