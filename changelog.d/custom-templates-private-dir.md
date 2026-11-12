### Security: one organization's custom templates are no longer readable by another's task

- `pkg/core`, `pkg/sensorkit`: custom templates (a scan's or a retest's) were written to the system's temporary directory, which the tool sandbox leaves readable. On a shared sensor, a task of another organization launched while a job ran could read that job's templates, including credentials in them such as auth headers. They are now written to a private directory under the task root, which the sandbox hides from every task, and only the tool runs of the job that carries them are granted it.
- New: `executor.WithReadPaths`/`ReadPathsFrom` carry a job's read grants on its context (`core.ExecuteScanner`, `StreamScanner` and the tool host apply them), and `executor.NewJobDir` makes a granted private directory. A scanner that copies, rewrites or signs the templates must make the copy with `executor.NewJobDir` and run its tool with the context it returns. A copy left in the system's temporary directory is still readable by other tasks.

### Upgrade notes

- A scanner that starts its tool outside `core.ExecuteScanner`, `core.StreamScanner` or the tool host, or without the job's context, no longer reads the job's custom templates in the sandbox, and the scan fails visibly. Run it through those paths with the job's context.
