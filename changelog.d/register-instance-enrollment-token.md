### Fixed: SENSOR_INSTANCE_ENROLLMENT_TOKEN is in the settings registry

- The variable was read by the kit but missing from the settings registry, so
  the config report did not list it and `docs/SETTINGS.md` and the README had
  no row for it. It is registered as a secret (never printed) and documented.
