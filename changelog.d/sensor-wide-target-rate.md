### Behaviour change: one view of each target host for every task of the sensor

- Task forwarders share each target host's rate across the sensor
  (`adapt.SensorRate`, joined with `HostRate.Share`; the tool host joins the
  process's one): two tools scanning one host no longer add up their rates.
  On a shared sensor the host's rate is split evenly between the tenants
  asking for it.
- A Retry-After one task got from a host now holds the other tasks of the
  same tenant too.
- An edge block (a vendor block or challenge page, or a run of 403 answers)
  cools the host down for the tenant's tasks: 15 minutes, doubling on each
  further block up to 6 hours. Connections toward it are refused before a
  path is chosen (no other proxy endpoint is tried) and the host is reported
  as a blocked coverage gap with the edge's vendor.
- Retry-After and cooldowns are kept per tenant and host; nothing a target
  told one tenant's scans reaches another tenant's tasks.
