### Security: a sensor that bound its own key pins the platform's job signer

- A sensor started with an API key that bound its own signing key (`SENSOR_KEY_BIND=auto`, the default) had no signed pairing grant, so no job signer was pinned: it ran with signed jobs `off`, verified no job, and could use no job's secret list (proxy-pool credentials were never fetched; the only trace was one refusal line).
- At its first start against a platform that signs jobs, such a sensor now pins the root of the platform's job-signing key set (or its signer keys) in `identity.json`, logs "Job signer pinned on first use", and requires signed jobs from then on, so a later platform compromise cannot swap the signer. Existing self-bound sensors pin at their first start after the upgrade.
- Not done when `SENSOR_JOB_SIGNING_KEYS` or `SENSOR_JOB_SIGNING_ROOT` is set, when `SENSOR_REQUIRE_SIGNED_JOBS=false` (a pin would stop the sensor; it warns instead), for a shared sensor, or for an identity that came from pairing.
- New `identity.JobSignerOnFirstUse`; the conformance `FakePlatform` gains `SignedJobs` (served on hello) and `TrustSensorKey` (accepts v2 requests signed by a key-bound sensor).

### Upgrade notes

- A self-bound sensor whose platform signs only some of its commands would refuse the unsigned ones after this upgrade. A platform that lists `signed_jobs` signs every command it hands out; if yours does not, set `SENSOR_REQUIRE_SIGNED_JOBS=false` before upgrading.
