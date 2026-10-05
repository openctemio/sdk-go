### Added: sensor pairing protocol and signed sensor requests

- `pkg/sensorproto/pairing`: the interactive pairing protocol of api
  RFC-052 (wire types, the nonce commitment, the platform transcript and
  its signature check with an optional pinned platform key, the short
  authentication string a person compares, user codes). Its test vectors
  are byte-identical with the platform's copy.
- `pkg/sensorsig`: RFC 9421 request signatures with the sensor's Ed25519
  key (one narrow profile: `@method` `@path` `@query` `content-digest`,
  created/expires/nonce/keyid, RFC 7638 key id) and a signing
  `http.RoundTripper` that never sends a bearer credential.
