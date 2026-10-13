### Added: discover.hosts@1 in the capability taxonomy and its conformance suite

- ctis is bumped to the taxonomy with `discover.hosts@1` (host discovery: light liveness probes on addresses and ranges, T1; out `ip` with `properties.live_by`), so tools can implement it.
- The tool conformance suite gains an active `discover.hosts@1` suite: a loopback address answering on one port, probed on that port, must be reported live with the probe that answered, and nothing the tool was not given may be reported.
- New `core.LiveHostsReport`: the host discovery mechanism a tool wrapper calls. It turns a port probe's report into the capability's report (each answering address of the job's targets as a live `ip_address` with `properties.live_by` = `tcp:<port>`, nothing else). `core.ErrNoProbePorts` is what a wrapper answers for a job without probe ports: the platform names them in every host discovery job, a sensor never picks its own.
