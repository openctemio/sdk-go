### Changed: `pkg/analyst` is now `pkg/harness`

- The AI runtime package is renamed to `pkg/harness` (with `pkg/harness/contract` and `pkg/harness/playbook`), because later AI roles (remediation, reports, hunting) run on the same loop. The package is Experimental, so there is no alias: change the import path.
