### Fixed

- **Executor**: a task no longer fails to start ("landlock: file does not
  exist") when a file the launcher listed while granting read access
  disappears before its rule is added (another task's temporary file in
  /tmp). The vanished path is skipped; it grants nothing.
- **Cancels reach a sensor without the doorbell** (api RFC-046 §8). A
  sensor started with the doorbell off (`sensorkit.Options.DisableDoorbell`,
  `-disable-doorbell`) sent plain heartbeats and ignored the answer, so a
  scan the user canceled, a run that hit its deadline or a command handed to
  another sensor ran to the end. The plain heartbeat now reads
  `cancel_command_ids` (`client.SendHeartbeatForCancels`,
  `core.CancelPusher`) and the poller (`core.CommandCanceler`) stops and
  releases those commands, as with the doorbell. The heartbeat itself is
  unchanged: it does not announce the doorbell.
