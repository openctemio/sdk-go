### Added: pin the platform CA by fingerprint

- `httpsec.SetAPIPinnedCA` / `httpsec.ParseCAFingerprint`: every API client
  created afterwards accepts the platform only when its TLS chain verifies
  up to the certificate with that SHA-256 fingerprint (a root or an
  intermediate the platform sends, or a self-signed platform certificate).
  The system trust store and `SENSOR_CA_FILE` no longer apply while a pin
  is set; the name, validity and key usage are still checked. This is what
  makes the first contact of a pairing sensor safe from a fake platform
  (api RFC-052).
