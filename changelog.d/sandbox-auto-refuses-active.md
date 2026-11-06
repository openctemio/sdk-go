### Security: SENSOR_SANDBOX=auto no longer runs active tools unconfined

- In `auto` mode on Linux, when the tool sandbox cannot be enforced (the
  launcher fails or is not wired, user namespaces are blocked, or Landlock is
  missing), tools of tier T1 and above are now refused with
  `unconfined_sandbox` instead of running with only a warning as the sensor's
  user, where they could read `signing.key`. Passive (T0) tools still run.
  `SENSOR_SANDBOX=off` stays the explicit acknowledgement; `required` still
  refuses to start.
- `executor.Status.FailedControls` and `UnconfinedDetail` say which control
  failed; the sensor log and the `runtime.sandbox_unconfined` check show them.
