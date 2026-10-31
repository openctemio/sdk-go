### Fixed: pairing explains a key the platform registered before

- A pairing start the platform refuses with `pairing-key-registered` (the key
  was approved once; a key pairs only once) returns `identity.ErrKeyRegistered`
  at once, with the identity directory and the fix in the message, instead of
  a raw `HTTP 409`. A `pairing-key-busy` answer (another open request holds the
  key) is retried with backoff like other transient refusals.
- New problem types `protov2.ProblemPairingKeyRegistered` and
  `protov2.ProblemPairingKeyBusy`.
