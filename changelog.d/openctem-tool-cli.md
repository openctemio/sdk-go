### Added: the `openctem tool` CLI and the conformance kit for the tool contract

- New command `cmd/openctem` with six `tool` subcommands (reference in `docs/tools/cli.md`):
  - `init --kind exec-sarif|exec-ctis|exec-json|go|python --capability <id@major>` scaffolds a tool from the capability. The scaffold passes `openctem tool test` as written.
  - `validate` checks the descriptor; errors carry JSON pointers.
  - `run` runs one task offline, through the sensor runtime.
  - `test` runs the conformance kit.
  - `diff` checks the version bump of a descriptor change.
  - `describe --json` prints the canonical descriptor and its digest.
- `openctem-conformance tool` is now an alias of `openctem tool test`, kept for one minor release.
- New in `pkg/conformance`:
  - `LintDescriptor`;
  - `RunContractSuite`:
    - every fixture is checked against the contract of each implemented capability;
    - per-capability suites on loopback fixtures cover `scan.ports@1`, `probe.http@1`, `vuln.templates@1`, `secrets.code@1`, `sast.code@1` and `sca.deps@1`;
    - the scope check;
  - `FuzzOutput` fuzzes the parser of an exec tool's output format;
  - `DiffManifests` gives the semantic version bump a descriptor change needs.
- CI templates `ci/github/openctem-tool.yml` and `ci/gitlab/openctem-tool.yml`, with actions pinned by commit.

### Security

- The kit runs a tool under test only through the runtime's host and sandbox, as a sensor would. Its fixtures listen on loopback only, and nothing is reached beyond them.
- Scope check: the tool is given one target while another address listens. Any connection to that address fails the check.
- `secrets.code@1` plants fresh fake credentials and fails when a raw value reaches the report or the logs, in any field.
- `diff` treats these as breaking changes that need a major version bump:
  - narrowing what a tool takes or emits;
  - raising its tier or adding a side effect;
  - adding a required config key.
