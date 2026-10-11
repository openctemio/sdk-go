### Added: one data volume for the sensor's state, outbox and content

- `sensorkit.DefaultDataDir` (`/var/lib/openctem`): sensors mount one
  persistent volume there, holding `state/`, `outbox/` and `content/`. The
  persistence check already judged a directory by its nearest mount, so a
  volume at `/var/lib/openctem` counts for the state directory (now tested);
  a volume on each subdirectory keeps working.
- The kit creates the state directory 0700 when it is missing (a bind mount
  or a Kubernetes volume does not get the image's directories), narrows a
  looser mode to 0700, and warns when another user owns it, with the
  `chown` to run.
- New config check `storage.outbox_persistent` (`persistent`,
  `not_persistent`, `unknown`): an outbox off any volume loses undelivered
  results when the container is recreated. A state directory or outbox off
  any volume is also said on the sensor's log at start.
