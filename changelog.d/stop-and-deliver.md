### Added: the platform can ask for what a stalled task finished

- A heartbeat answer may carry `stop_command_ids`: held commands the platform asks the sensor to stop and complete with what they finished (the task stalled). The poller cancels the run with `core.ErrStoppedByPlatform`; the tool host treats it like a stop by the job's own budget (the settled targets' records are delivered, the task ends `partial` with the rest in `unfinished_targets`), the executor parses and pushes under a context the stop does not end, and the result is reported, not released. A run that settled nothing is reported failed, and the platform re-queues it.
- `cancel_command_ids` is unchanged: a canceled command delivers nothing and is released.
- Needs the heartbeat doorbell (on by default); a sensor without it ignores stops, and the platform re-queues the task after a grace period.
