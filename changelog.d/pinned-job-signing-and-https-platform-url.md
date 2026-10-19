### Security: pinned job-signing keys cannot be turned off by env; plain-http platform URLs are refused

- On a sensor whose identity pinned job-signing keys or a root at pairing, `SENSOR_REQUIRE_SIGNED_JOBS=false` is now a usage error (it may only raise the requirement). The one escape is `SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS=1`, for development: the sensor warns at start and for every unsigned job it accepts (`core.JobGuard.AllowUnsignedJobs`).
- A sensor with no pinned key (posture `off`) now warns at start whatever the verbosity; the posture is already part of the posture report sent to the platform.
- `httpsec.CheckAPIBaseURL` returns an error for a plain `http://` platform URL to a host that is not loopback (it was a warning). `SENSOR_ALLOW_INSECURE_HTTP=1` (development only) turns the error back into a warning.
- The sensor warns at start when the test switch `OPENCTEM_SDK_HTTPSEC_ALLOW_LOOPBACK` is on.

### Upgrade notes

- A sensor that sets `SENSOR_REQUIRE_SIGNED_JOBS=false` while it pinned keys at pairing now refuses to start; remove the variable. A platform URL that is `http://` to a non-loopback host must move to `https://`.
