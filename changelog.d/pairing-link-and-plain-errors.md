### Added: the sensor prints the link to approve it on

- When the platform sends it (`verification_uri_complete`), `identity.Pair` prints `Pair this sensor: open <console>/activate?code=XXXX-XXXX` with the code and the fingerprint, whether the sensor started with a code or without one. A started-with-code sensor shows the same code the console's command carried. The link is printed only when it is an absolute http(s) URL of printable characters (no terminal control sequence from the platform reaches the operator's screen), and a resumed request prints it again.
- The output asks the operator to pick this fingerprint in the console (the console now offers three and the platform checks the pick).

### Fixed: an untrusted platform certificate is explained once instead of retried silently

- A TLS chain signed by an authority the host does not trust (a private CA, or TLS interception) stops the retry loop with one sentence naming the presented authority's SHA-256 fingerprint and the fix (the console's command installs the CA, or `SENSOR_CA_CERT_FILE`), then waits like any other refusal (`UntrustedTLSError`).
- A refused request now says it may have been closed by a wrong fingerprint pick, and the spent-code message points to the new link instead of console menu names.
