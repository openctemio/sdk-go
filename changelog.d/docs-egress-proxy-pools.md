### Documentation: organization proxy pools for scan traffic

- `docs/SECURITY.md` explains how a job's proxy pool is applied (scope check first, tunnels by address, failover rules, breaker, endpoint validation, credential handling, where pooled jobs are refused), the `SENSOR_SCAN_EGRESS` veto and `SENSOR_SCAN_EGRESS_ALLOW`, and that HTTP proxies must allow CONNECT to the scanned ports; the README settings table lists both settings.
