### Security

- A confined task (`executor.Config.ConfineNetwork`, the sensor's `SENSOR_SANDBOX_NETWORK`) now runs in its own PID namespace, with the launcher as its init. A tool can no longer signal the sensor or another task running as the same user (on a shared sensor, another tenant's job), a process that leaves the task's process group with `setsid` no longer outlives the task, and the launcher reaps the tool's orphans. No operator action: the sensor's seccomp profile already allows the namespace.
- The per-task seccomp filter refuses `io_uring_setup`, `io_uring_enter` and `io_uring_register`. This matters most where the sensor runs without the container profile (a VM or bare-metal install); the container profile already refused them.
