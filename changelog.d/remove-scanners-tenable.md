### Upgrade notes

- `pkg/scanners/tenable` is removed. Nothing in the sensor, the platform or the asset collector imported it. Convert `.nessus` exports with `github.com/openctemio/ctis/importer` (`importer.Parse` with format `nessus`), which reads the same NessusClientData_v2 format with credential redaction and the CTIS limits.

### Removed

- `pkg/scanners/tenable`: the deprecated Nessus REST client and `.nessus` converter.
