### Fixed: a sensor no longer claims a job for every slot its own claims made up

- The resource manager counts the memory of running jobs back as budget, so the slot count does not shrink because jobs run. It counted every running job, including one claimed after the (cached, up to 10 s old) probe or one still starting: the probe did not show that job's memory yet, so each claim added a slot, and a sensor with room for one job claimed a second, third, ... until the CPU bound. Once those jobs took their memory the sensor reported fewer slots than the jobs it held (for example 2 jobs running, 1 slot).
- Only jobs that had run for `ManagerConfig.JobSettle` (default 3 x `ProbeInterval`, 30 s) when the probe was taken count back now. A host shared by several sensors no longer gets more jobs than its free memory fits.
- `ProbeResult.At` is when a probe was taken.
- The poller's "Not polling: all N slots busy" line names the live slot count and the jobs running, not its upper bound (64 without `SENSOR_MAX_JOBS`).
