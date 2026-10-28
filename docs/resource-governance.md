# Resource governance

A scan tool needs CPU, memory and disk I/O to start and to run. On a host that
other heavy programs share (CI runners, build agents, databases), every
runnable task can wait for a CPU or for the disk while the host's CPU and
memory use still look plausible. A tool started into that stall cannot even
complete its start handshake, and used to be reported as crashed. The SDK
measures that stall, holds launches while it lasts, bounds each tool's
resources, and tells a slow start from a crash.

Everything here lives in the SDK core (`pkg/resource`,
`pkg/sensorkit/toolhost`, `pkg/sensorkit/executor`): a sensor built on
sensorkit gets it without code, and a tool gets it by declaring its
`resources` in `tool.yaml`, built-in and third-party tools alike.

## Host pressure

Every probe (10 seconds) reads, where available:

| Signal | Source |
|---|---|
| CPU stall | Linux PSI `/proc/pressure/cpu` and the sensor cgroup's `cpu.pressure` (the larger counts) |
| CPU quota throttling | the sensor cgroup's `cpu.stat` (`nr_throttled` over `nr_periods`) |
| Memory stall | `/proc/pressure/memory`, `memory.pressure` (`some` and `full`) |
| I/O stall | `/proc/pressure/io`, `io.pressure` (`some` and `full`) |
| Load per CPU | `/proc/loadavg` over the host's CPUs, only where PSI is missing |
| Available memory | `MemAvailable`, or the cgroup's limit minus its usage |
| Open descriptors | the sensor's own against its limit, and the host's table |
| Foreign CPU | the host's busy CPU minus what the sensor and its tools used |

An unreadable signal is unknown and never raises the level.

The governor rates them as `ok`, `elevated` or `overloaded`:

| Signal | elevated | overloaded |
|---|---|---|
| CPU stall (`some`, 10 s average) | 40 % | 75 % |
| CPU quota throttling | 30 % | 60 % |
| Memory stall `some` / `full` | 10 % / 2 % | 30 % / 10 % |
| I/O stall `some` / `full` | 40 % / 10 % | 70 % / 30 % |
| Load per CPU (without PSI) | 1.5 | 3 |
| Available memory | under 15 % | under 5 % |
| Open descriptors | 80 % | 95 % |

A higher level is entered on the first probe over a bound. A level is left
only after two probes in a row under 70 % of its bounds, so it does not flap.
The heartbeat's `resources.pressure` carries the level, the reasons (`cpu`,
`memory`, `io`, `load`, `mem_available`, `fds`), the readings and
`noisy_neighbor`: set when the host is pressured and processes outside the
sensor use at least half of its CPU.

## What pressure changes

- **Slots.** `elevated` halves the job slots; `overloaded` leaves no free slot
  while any job runs, and one when none does. The heartbeat's `slots_free`
  says so, and the platform hands the sensor nothing more until it recovers.
  Overload also halves the slot controller's window, so the slots grow back
  one at a time.
- **Launches.** Before a tool process starts, the tool host asks the governor.
  While the host is overloaded the launch waits (the command log says why),
  unless no tool of the sensor runs: one tool always runs, so a host that
  stays loaded still makes progress one tool at a time. A held launch never
  outlives its job's time budget. The heartbeat's `capacity.launches_held`
  counts held launches.
- **Start handshake.** The 30-second handshake timeout is multiplied by 2 when
  elevated and by 4 when overloaded (or by `1 / (1 - CPU stall share)` when
  larger), at most 120 seconds.

## Slow start or crash

When the handshake does not come, the tool host looks at the process: alive
with almost no CPU time since it started is a starved start (`slow_start`),
not a crash. The task is started once more, after a two-second backoff and
the governor's admission, when the first attempt settled nothing and it ended
as:

| First attempt | Retried |
|---|---|
| slow start | yes |
| no handshake from a busy process, host elevated or overloaded | yes |
| killed by the kernel for memory, host elevated or overloaded | yes |
| the kernel refused the fork (`EAGAIN`, `EMFILE`, `ENFILE`, `ENOMEM`) | yes |
| killed at its own envelope's memory limit | no (the tool needs more memory) |
| a policy refusal, manifest or protocol mismatch, an exit before the handshake | never |
| anything after a record or a settled target | no |

The outcome carries `Attempts` and `Transient`; a recovered start logs
"started on the second attempt" to the command log. A start that fails again
under pressure is reported as `infra.resource.host_pressure` with the
attempts and the level in its evidence: a fact about the host, which the
platform may answer by moving the task, never by holding it against the tool.
A platform that does not list the `host_pressure` feature receives
`infra.tool_crashed` as before. Only the runtime sets these fields; nothing a
tool writes can turn its own failure into the host's.

The heartbeat's `capacity.transient` counts handshake timeouts, slow starts,
OOM kills, refused forks, retries and recoveries since the sensor started.

## Per-tool envelope

`resources.profile` in `tool.yaml` sizes each task:

| Profile | CPU (cores) | Memory | Processes |
|---|---|---|---|
| `light` | 1 | 512 MiB | 256 |
| `standard` (default) | 2 | 2 GiB | 512 |
| `heavy` | 4 | 4 GiB | 1024 |

`resources.cpu` and `resources.memory` override the profile's values.

Where the sensor's cgroup (v2) is delegated to it and holds the sensor alone
(systemd `Delegate=yes`, or a container whose main process is the sensor and
whose cgroup mount is writable), the sensor moves itself into a leaf cgroup
and starts every task directly inside a cgroup of its own
(`clone3` with `CLONE_INTO_CGROUP`) with `cpu.max`, `cpu.weight` 50 (the
sensor keeps 100), `memory.max` and `pids.max`. Nothing the tool forks is
outside its limits, and an out-of-memory kill at the envelope's limit is told
apart from the host's. The sensor never writes outside the cgroup it was
started in and needs no privilege. `SENSOR_TOOL_CGROUPS=off` turns this off.

Elsewhere the envelope becomes rlimits of the sandbox launcher (data twice the
memory limit, at least 1 GiB; processes), next to the scanner priority
(nice +10, idle-class I/O, a higher OOM score). The sandbox status says which
envelope tasks get (`envelope`, `envelope_missing`).

## Testing

`scripts/fault-injection.sh` runs a CPU hog and memory pressure under a CPU
quota and a memory limit, and the cgroup envelope, each in a throwaway
container. It never mounts the host's Docker socket.
