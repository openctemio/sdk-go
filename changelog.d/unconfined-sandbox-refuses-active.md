### Security: tools that contact their targets no longer run unconfined without the operator saying so

- With `SENSOR_SANDBOX=auto` (the default) on a host where the tool sandbox is not available (it is Linux only: every macOS or Windows sensor), tools ran as plain child processes with only a start-up warning. The tool host now refuses tools of tier T1 and above (they contact their targets) on such a host, with refusal `unconfined_sandbox` (`core.RefusalUnconfinedSandbox`); passive T0 lookups still run. `SENSOR_SANDBOX=off` is the explicit acknowledgement that every tool runs unconfined.
- A Linux host where the sandbox could not start keeps today's behaviour (the start-up warning and `Status.Missing` say why).
- New `executor.Status.NoSandboxOnHost`, `Unconfined()` / `RefusesActiveTools()`, manifest posture `sandbox.unconfined` (`refused`, `acknowledged`) and config report check `runtime.sandbox_unconfined` (`sandboxed`, `active_refused`, `acknowledged`).
- Upgrade note: a sensor that relied on `auto` running tools unconfined must now set `SENSOR_SANDBOX=off` to keep running T1 tools there.
