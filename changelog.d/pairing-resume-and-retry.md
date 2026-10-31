### Fixed: pairing resumes after a restart and a re-pair no longer destroys the working identity

- The pairing request in flight is kept in `identity/pairing.json` (0600). After a restart the sensor polls it first: an approved request is confirmed (no new request, no ghost registration), a pending one shows the fingerprint again, and an expired, refused or unknown one is replaced by a new request.
- `Store.RotateKey` (`pair -repair`) now stages the new key in `signing.key.next`; `signing.key` and `identity.json` are replaced together only after the platform confirmed (`Store.SaveAndPromote`). An interrupted, refused or expired re-pair leaves the working identity untouched, and a later re-pair reuses the staged key. `Store.Load` finishes a promotion that crashed half-way. `Store.Check` covers the two new files.
- A pairing code is single use: the sensor never resends the code of a request that expired or was refused. The daemon continues with a request without a code and prints why; `pair` exits with the same explanation.
- A key the platform reports as already registered (`pairing-key-registered`) with no confirmed identity on this host is replaced once. With an identity the sensor stops (the daemon waits) and asks for a restore or an administrator's Re-pair.

### Changed: pairing retries use full jitter and no longer exit on an unknown 4xx

- Every pairing backoff is a random delay between half of the base and the base (5 seconds doubling to 5 minutes); `Retry-After` (1 to 300 seconds, plus jitter) is honoured on any answer, including the new `pairing-key-busy` problem. Retried: network errors, HTTP 408, 425, 429, 500, 502, 503, 504, clock skew.
- Any other HTTP answer in daemon mode is no longer an exit into a supervisor restart loop: the problem's title and detail are printed once and the sensor tries again no sooner than 5 minutes later. `pair` still exits, now printing the title and detail (the raw answer when it is not a problem document).
- `sensorproto/v2` names the problem types `pairing-not-found`, `pairing-key-registered` and `pairing-key-busy`.
