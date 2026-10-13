### Added: retest commands carry the job's web scope

- A `retest` command's `web_scope` (as on a scan command) now reaches the tool's retest task (`tool.Task.WebScope`). The tool host enforces it: on a sandbox that confines the network, the task forwarder checks every request, and a tool that does not declare `features.web_scope` is refused. An invalid scope fails the command before anything runs. Before, the field was dropped, so the platform had to refuse retests of findings on hosts with a path exclusion.
- Conformance: `RunContractSuite` runs a web-scoped retest (`Retest/web_scope`) for a tool that declares `features.retest` and `features.web_scope`, and fails when the tool requests a denied path. `LintDescriptor` warns about a networked retesting tool without `features.web_scope`.
