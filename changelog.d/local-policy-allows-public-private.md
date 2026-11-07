### Added: the local policy report says whether public and private targets can pass

- The local policy report (manifest and every heartbeat) gains two booleans,
  `allows_public` and `allows_private` (`core.LocalPolicyReport.AllowsPublic`,
  `AllowsPrivate`). The platform can refuse at plan time a scan this sensor
  would refuse at run time, for example a public target on a sensor whose
  `SENSOR_ALLOWED_RANGES` holds only `10.0.0.0/8`, even while the sensor is
  offline.
- Without a policy: `allows_public` is true and `allows_private` follows the
  host's consent (`SENSOR_ALLOW_PRIVATE_TARGETS`); both are false when a
  required policy is absent.
- The ranges themselves are still never sent: only the two booleans.
