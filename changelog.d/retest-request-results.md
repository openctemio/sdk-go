### Added: a retest verdict can report each request the check made

- `tool.RetestVerdict`, `tool.VerdictReport` and the adapter `verdict` message carry optional `requests` (`tool.RequestResult`: URL, status, matched, error class, edge vendor and state), at most `tool.MaxVerdictRequests`. A check that probes several paths reports them so the platform can judge the finding's own endpoint. Additive and wire-compatible: older platforms ignore the field, and older tools simply omit it.
