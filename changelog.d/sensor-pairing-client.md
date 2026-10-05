### Added: key-bound sensors pair on first start (api RFC-052)

- `pkg/sensorkit/identity`: the sensor's identity on disk
  (`<state dir>/identity/signing.key`, PKCS #8 PEM, and `identity.json`,
  both 0600 in a 0700 directory owned by the sensor's user) and `Pair`, the
  interactive pairing client: the sensor makes its own Ed25519 key, checks
  the platform's signed answer (and its pinned key), prints a code and a
  fingerprint for the administrator to compare, waits for approval and
  confirms the identity with a signature. No secret is ever typed or
  pasted.
- `client.Config.Signer`: a key-bound client signs every request (RFC 9421,
  `pkg/sensorsig`), heartbeats included, and never sends a bearer key.
- The kit: a sensor started without `API_KEY` uses its paired identity, or
  pairs on first start and then runs (`Options.NoAutoPair` stops it
  instead). `SENSOR_CA_FINGERPRINT` pins the platform's TLS chain;
  `SENSOR_PLATFORM_KEY` pins the platform's pairing key.

### Security

- The sensor refuses to start when its identity directory or files are
  readable by others, owned by another user or symbolic links, and prints
  the exact `chmod`/`chown` to run.

### Behaviour change

- `API_KEY` is no longer required: a sensor without one pairs instead of
  exiting with "missing: [API_KEY]". Set `Options.NoAutoPair` to keep the
  old refusal.
