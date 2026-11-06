### Security: pairing saves only what the platform signed

- The platform's approval and confirm answers carry a signed grant
  (`pairing.SignedGrant`, member `grant`): the identity, the content-signing
  keys, the job signer's keys and key set, and the root CAs of the
  platform's TLS certificate when it knows them, signed with the pairing key
  of the start answer that the administrator's fingerprint check covers. It
  names the pairing id, the sensor's key and the nonce the sensor revealed,
  so it cannot be replayed to another sensor or request.
- `identity.Pair` verifies the grant before it confirms and again on the
  confirm answer, and saves only what that grant states. Before, someone in
  the middle of the first pairing could relay the start untouched (the
  fingerprints matched) and swap the job-signing keys, the content keys or
  the TLS pin the sensor learned afterwards.
- A missing or invalid grant, a grant for another request, key or nonce, or
  a TLS anchor the grant does not name stops pairing with an error naming
  the step and `pairing_answer_unsigned`; nothing is saved.
- New: `pairing.Grant`, `SignGrant`, `VerifyGrant`, `GrantTranscript`,
  `identity.ErrTLSAnchorMismatch`, `conformance.RunPairingGrantSuite`; the
  shared pairing vectors gain `grant_payload` and `grant_signature`.

### Behaviour change: a new sensor does not pair with a platform that does not sign its answers

- A platform from before signed pairing answers is refused with "upgrade the
  platform"; there is no fallback to the unsigned identity. Platforms only
  add the member, so sensors from before it still pair with a new platform.
- Pairing no longer reads the hello for the job signer: it comes from the
  grant. A request saved in `pairing.json` by an older SDK (no sensor nonce)
  is not resumed; a new request starts.
