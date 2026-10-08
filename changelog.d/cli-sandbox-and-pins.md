### Fixed: openctem tool runs tools in the sensor's sandbox, and scaffolds pin the SDK they need

- `openctem tool run` and `test` (and `openctem-conformance tool`) installed no executor backend, so tools ran as plain child processes while the docs said they ran in the sensor's sandbox. A tool that only worked outside the sandbox passed the kit and failed on a sensor. They now run in the process sandbox: `--sandbox off|auto|required`, default `$OPENCTEM_SANDBOX`, else `auto`.
- `init --kind go` wrote `require github.com/openctemio/sdk-go v<sdk.Version>`, a release older than the descriptor keys the CLI writes (`implements`), so the scaffold panicked on its own `tool.yaml`. The scaffold now requires the SDK version the CLI was built from, and its CI workflow installs the CLI at that version instead of `@latest`.
- `openctem tool run .` failed with `fork/exec bin/<tool>: no such file or directory`: the manifest path is now made absolute, as `test` already did.
- `docs/adapter-protocol.md` no longer says an operator-installed tool runs only on a backend that enforces the network class. The process sandbox does not enforce it yet.
