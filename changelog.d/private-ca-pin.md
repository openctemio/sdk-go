### Added: SENSOR_CA_SHA256 makes a sensor trust a private platform CA by itself

- With `SENSOR_CA_SHA256=<root sha256>` (comma separated for rotation) a sensor whose platform certificate comes from a private CA fetches the platform's public CA bundle and trusts only a certificate that matches the pin and signs the chain the server presents; it keeps it in its state directory. Without a pin nothing is trusted automatically. `SENSOR_CA_CERT_FILE` still works for air-gapped hosts.

### Changed: clearer untrusted-certificate errors

- The error lists every certificate the platform presented (name and SHA-256) and names the root authority the top one needs (the platform does not send it). A `SENSOR_CA_CERT_FILE` that cannot be read or is not PEM is refused with its path, and one that holds only an intermediate is called out.
