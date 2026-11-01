### Fixed: a job its own time budget stopped fails as `infra.budget_exceeded`, not `unknown`

- When a scan job's time budget (its `timeout_seconds`, task budget or the platform's `deadline`) ends the run before the tool settled anything, the failure is now classified `infra.budget_exceeded` (error code `TIMEOUT`) instead of `unknown`. The tool's error is kept (`errors.Is` still finds `context.DeadlineExceeded`). A cancel is not affected.
- When the platform's `deadline` had already passed before the job started (the job then gets only `MinDeadlineBudget`, 30 s), the failure carries the reason `deadline_passed`, so the platform and the operator see that a stale deadline, not the tool or the targets, ended the job.
