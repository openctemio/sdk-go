### Added: a sensor enrolls as a shared sensor with SENSOR_INSTANCE_ENROLLMENT_TOKEN

- A sensor with no identity and `SENSOR_INSTANCE_ENROLLMENT_TOKEN` set (a single-use token a super administrator issued, or one the install registered for its bundled sensor) runs the usual key-bound pairing with the token in the signed start request and is enrolled as a shared sensor of the instance, without an administrator's approval (api RFC-100 §7).
- `identity.PairOptions.EnrollmentToken`, `pairing.StartRequest.EnrollmentToken`, `pairing.Identity.Scope` (`pairing.ScopeInstance`) and `identity.Identity.Scope`. With a token the identity must be a shared sensor's (no tenant); without one, an identity without a tenant is refused.
- A refused token (`identity.ErrEnrollmentRefused`) or an expired request stops the sensor; a spent token never starts a second request. The token is never printed; it cannot be combined with `SENSOR_PAIRING_CODE`, and it is ignored (with a note) once the sensor is paired.
