### Added: pin the platform CA by fingerprint

- `httpsec.SetAPIPinnedCA` / `httpsec.ParseCAFingerprint`: every API client
  created afterwards accepts the platform only when its TLS chain verifies
  up to the certificate with that SHA-256 fingerprint (a root or an
  intermediate the platform sends, or a self-signed platform certificate).
  The system trust store and `SENSOR_CA_FILE` no longer apply while a pin
  is set; the name, validity and key usage are still checked. This is what
  makes the first contact of a pairing sensor safe from a fake platform
  (api RFC-052).
- With a pin, the platform URL must use a host name: crypto/tls sends no server name for an IP address and x509 would skip the name check, so a pinned connection to an IP address is refused (`ErrPinnedCANoServerName`).

### Fixed: guarded clients try every validated address

- The SSRF-guarded dialer resolved every address of a host, checked them all, and then dialled only the first. A platform or target name with an IPv6 and an IPv4 address failed to connect when only one family was reachable. It now tries the validated addresses in resolver order; no unchecked address is ever dialled.
