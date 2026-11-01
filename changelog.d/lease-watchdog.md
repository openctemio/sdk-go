### Behaviour change: a job whose lease cannot be renewed is stopped, and its results are not sent

- During a network loss longer than a job's lease plus a grace (a quarter of
  the lease, at least 30 seconds; 3 minutes 45 seconds with the platform's
  default lease), the sensor now stops the job (`core.ErrLeaseLost`). The
  platform hands the job to another sensor at that point, so the two no
  longer scan the same targets. Nothing of the stopped job is reported,
  released or sent afterwards, bound or unbound (`Client.MarkLeaseLost`).
  Before, the job kept running and its late results were dead-lettered or
  re-sent without their command.
- Only durations are compared with the sensor's clock (clock skew never
  decides a stop), and the watchdog arms at the first answered heartbeat.
- Bound results (`PUT …/commands/{id}/results/…`, segments and commit) now
  carry `X-OpenCTEM-Lease-Epoch` from the claim, so the platform refuses
  results of a run it has handed out again.
