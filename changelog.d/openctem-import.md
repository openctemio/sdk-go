### Added: `openctem import` converts and imports the output of tools you run yourself

- New subcommand of the `openctem` CLI: `tool ... | openctem import --format <f>` (or files) converts nmap XML, testssl.sh JSON, line lists of names, addresses or URLs (`--format lines --as host|domain|ip|url|auto`), any other ctis importer format, a CTIS report, or any JSON/CSV/XML through a local declarative mapping file (`--mapping`), into a CTIS report on your machine.
- `--dry-run` prints the report (exactly what would be sent) and a summary; `--out <file>` writes it (mode 0600) for a later `openctem import <file>`; otherwise it is uploaded as `format=ctis` to `POST /api/v1/findings/imports` with the API key in `OPENCTEM_API_KEY` (never a flag) to `OPENCTEM_URL`, and the receipt is followed (`--wait`) and summarised: findings created/updated/skipped, assets created/updated, hosts held outside the organization's scope, refusals by reason.
- Exit status for CI: 0 imported, 1 refused or failed, 2 usage or input error, 3 still queued at the end of `--wait`.
- Security: the key is sent only over HTTPS (plain HTTP only to a loopback address) and never to a redirect target; server and input text is printed without control characters; inputs are bounded (100 MiB each, 10 per upload). Needs a console that accepts CTIS uploads (`format=ctis`).
- `file-import` (sensor importtool) 1.2.0 lists `nmap`, `testssl` and `ctis` among its formats (auto detection already reads them).

### Added: `openctem targets export` and `openctem run` give your own tools their input

- `openctem targets export --type domain|ip|url|service [--scope in_scope|not_covered|internal|all] [--tag t] [--export-format lines|json]` prints the organization's assets of one kind through `GET /api/v1/assets` with the API key's data scope; by default only assets an active scope entry covers. Values are de-duplicated and printed without control characters.
- `openctem run --type <kind> --format <f> [import flags] -- <command> ...` exports the targets to a private temporary file, runs your command without a shell with `{targets_file}` and `{output_file}` replaced, and imports what it wrote (`{output_file}`, else its standard output). The command does not inherit `OPENCTEM_API_KEY`; the temporary directory is removed afterwards.
