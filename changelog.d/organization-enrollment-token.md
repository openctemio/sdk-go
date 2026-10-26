### Added: organization enrollment tokens (SENSOR_ENROLLMENT_TOKEN)

- A sensor with no identity and `SENSOR_ENROLLMENT_TOKEN` (or `SENSOR_ENROLLMENT_TOKEN_FILE`) set enrolls in the organization that created the token (platform: Sensors > Enrollment tokens), through the usual key-bound pairing. The start request carries `enrollment_scope: "organization"`; the identity must name an organization (a shared-sensor answer is refused), and the sensor prints its fingerprint in case the token requires an administrator's approval. The token is never printed, is taken out of the environment once used, and cannot be combined with `SENSOR_PAIRING_CODE` or `SENSOR_INSTANCE_ENROLLMENT_TOKEN`.
- An expired request is retried with the same key (the platform counts a token use per key), so a sensor waiting for approval keeps waiting instead of exiting.
- `SENSOR_INSTANCE_ENROLLMENT_TOKEN` is unchanged: an instance token only, and only a shared-sensor identity is accepted for it.
- The pairing instructions name the console's current place: Sensors > Add sensor.
