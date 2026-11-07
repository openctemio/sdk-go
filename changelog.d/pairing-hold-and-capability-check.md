### Behaviour change: a pairing stop keeps the sensor up and a restart honours it

- A refused enrollment token, an approval or confirm answer without a valid
  platform signature (`pairing_answer_unsigned`; nothing is saved, as
  before), a TLS anchor mismatch and a platform that does not sign pairing
  answers no longer stop the daemon. It stays up, records a hold in
  `identity/pairing-hold.json` (15 minutes, doubling with each stop in a row
  up to 6 hours) and tries again when it ends. A restart within the hold
  waits the rest of it without calling the platform, so a restart loop no
  longer runs into the platform's rate limit (HTTP 429). A new token or
  pairing code ends the hold at once. The `pair` command still exits with
  the error.
- New: `identity.PairOptions.HoldOnStop` (on in sensorkit), `identity.Hold`,
  `identity.HoldFile`, `Store.LoadHold`, `SaveHold`, `ClearHold`.

### Added: the sensor checks before pairing that the platform signs pairing answers

- Before a new pairing request starts, the sensor reads the platform's
  hello once. A platform that lists its features without
  `pairing_answer_signed` is refused before any request exists, with
  `identity.ErrPlatformUnsignedPairing`, which names the platform version to
  upgrade to (`pairing.MinPlatformSignedGrant`, v0.21.0) and the older
  sensor release to pair with instead. A platform that serves hello only to
  paired sensors pairs as before; the signed grant is still verified.
- New: `protov2.FeaturePairingAnswerSigned`, `pairing.MinPlatformSignedGrant`.
  A missing grant now names that version too.
