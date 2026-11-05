### Security: a job's secrets reach a tool sealed, per task, from the job's signed list

- The values a task's tool receives (third-party provider keys) and the job's proxy pool credentials now come from one fetch, `client.Secrets` (`POST /api/v2/sensor/commands/{id}/secrets`, v2 HTTPS only, contract `secretref`). Only the refs the job's verified signed payload lists (member `secrets`) are asked for; the request is signed by the sensor's key-bound identity and carries the lease epoch and a single-use HPKE reply key in its signed body; the answer is sealed to that key and checked against the job's list. A bearer-key sensor never fetches.
- A shared sensor never fills a slot with its operator's local value, whatever the job says, and passes no vendor environment namespace (`PDCP_*`, `TRIVY_*`, ...) to an organization's task. On an organization's sensor a local value fills a slot only where the signed list allows it. A failed fetch, a gateway 404 or an answer that does not open gives no platform value and no other source; a required slot without a value fails the task (`secret_missing`); a job that requires a secret kind the sensor does not know is refused (`secret_kind_unsupported`).
- A tool of network `egress-proxy` (any public host) receives no platform secret; a provider key goes only to a tool of network `vendor` that its provider lists, and the task's network scope then admits that provider's hosts only when its key was delivered. On a shared sensor a task receives no platform secret without Landlock.
- Everything a task sends out (logs, records, verdict evidence, report info, artifacts, stderr, outcome) is scrubbed of each delivered value and its base64, URL and JSON encodings, Basic authorization forms and pair parts (forms of 8 characters or more).
- `tool.WriteSecretFile` writes a credential file 0600 with `O_EXCL` into the task's directory; a sensor removes the task directories an earlier run left behind at start, and its configuration report warns (`runtime.task_root_memory`) when the task root is not in memory.
- The egress report carries the command's lease epoch in its body (`protov2.EgressReport.LeaseEpoch`).

### Upgrade notes: one sealed fetch replaces the tool and proxy credential fetches

- Ships with the platform release that serves `POST /api/v2/sensor/commands/{id}/secrets` and adds the `secrets` member to signed jobs; a sensor on this SDK gets no platform values from an older platform (it never falls back to another route) and refuses a pooled job whose pool needs credentials.
- A sensor must be key-bound (signed requests) to receive platform values.
- Code that called `client.EgressCredentials` or wired `SetEgressCredentials`/`SetToolCredentials` wires `CommandPoller.SetSecretsFetcher(client)` instead (`sensorkit` does it).
- A tool that writes a credential file uses `tool.WriteSecretFile`; set `TMPDIR` to a tmpfs (or mount one at `$TMPDIR/openctem-tasks`) so such files never reach a disk.

### Added: passive target-scan tools of network vendor

- A target-scan tool may declare `network: vendor` with its `vendor_hosts`: it asks its vendor hosts about its targets and never contacts them. Its connections go through the job's proxy pool like any other task's; per-target scope limits hold on a sandbox that confines the network; a refused connection does not mark its targets unreached.

### Removed: separate tool and proxy credential fetches

- `client.ToolCredentials`, `client.EgressCredentials`, `core.ToolCredentialSet`, `core.JobToolCredentials`, `core.ErrToolCredentialsUnsupported`, `core.MergeToolCredentials`, `core.WithToolCredentials`, `core.ToolCredentialsFrom`, `core.EgressCredentials`, `DefaultCommandExecutor.SetToolCredentials`, `DefaultCommandExecutor.SetEgressCredentials` and the `protov2` `ToolCredentials*` and `EgressCredentials*` types are removed, with no alias: both kinds of value come from `client.Secrets` (wire it with `CommandPoller.SetSecretsFetcher`; `sensorkit` does). The platform serves `/secrets` in the same release and no longer serves `/egress-credentials`.
