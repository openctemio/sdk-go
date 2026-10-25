### Fixed: a silent host can no longer keep a finished task (and its command) open

- The egress forwarder closes every connection it serves, on both sides, when it stops; before, a plain HTTP request or a tunnel to a host that accepted the connection but never answered kept its handler blocked after the tool gave up and exited, the tool host waited for the forwarder forever, and the command never reported its result or honoured a cancel.
- An upstream connection whose host sends nothing for `egress.Limits.UpstreamIdle` (new, default 2 minutes, negative turns it off) is closed while the task runs. A tunnel cut this way after the host answered is not counted as a host failure by the adaptive rate.
- The tool host waits at most 10 seconds for a task's forwarder to stop, and at most another grace period for a killed tool to be reaped, then finishes the task with a warning line instead of hanging.
- A repeated platform cancel for the same command is a no-op: the command poller logs "Canceling command" once, not on every heartbeat. A cancel that arrives before the command's context exists is no longer swallowed.
