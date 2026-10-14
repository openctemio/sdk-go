### Added: a held command frees each host as soon as its targets settle

- The local queue tracks each held command's hosts with ctis `politeness.Holding`. When the job reports a target done (`Progress.TargetDone`), the hosts no pending target of it needs are freed at once. A command for the same hosts, from the next tool, is then admitted before the first command ends.
- The freed keys are reported on the heartbeat (`CommandProgress.ReleasedKeys`, `released_keys`), so the platform stops counting them as held and offers that work too.
- A freed host ends the claim backoff and wakes a poll that waits for a free slot.
- A target the command never had, or one settled twice, frees nothing. A bucket marker stays held while a pending address of its bucket does.

### Upgrade notes

- Internal: `localQueue.setProgress` takes a callback. No exported API changed except the new `CommandProgress.ReleasedKeys` field.
