### Added: zero-code tools for any JSON CLI and for every ctis importer format

- An exec-profile tool can write `json` or `jsonl` output with a mapping file:
  - `run.output: {format: jsonl, from: stdout, mapping: mapping.yaml}`;
  - the mapping uses the declarative language of `ctis/importer/mapping`, in JSON or YAML;
  - the runtime turns each record into CTIS, and the tool needs no code.
- An exec-profile tool can also write a named format of `ctis/importer`: `nuclei`, `semgrep`, `trivy`, `betterleaks`, `gitleaks`, `grype`, `zap`, `vuls`, `cyclonedx`, `spdx`, `osv`, `csaf`, `openvex`, `nessus`, `qualys`, `defectdojo` (`tool.ImporterFormats`).
- `LoadManifestFile` loads the mapping file and records its digest in `run.output.mapping_digest`, which the manifest digest covers. `tool.LoadMappingFile` loads a mapping file on its own.
- Parser and mapping issues appear in the outcome's logs, at most 10.

### Security

- The mapping file is part of the contract:
  - it must be a regular file inside the manifest's directory (no symlink, no `..`), of at most 256 KiB;
  - a bad mapping file refuses the tool at load;
  - a mapping file changed after load, or a missing one, refuses the task before the tool starts.
- The mapping language is closed (paths, constants, templates, a fixed set of transforms, bounded RE2 predicates; no code). It is bounded by the task's output limits.
- The report's tool is always the manifest's, never one the output claims.
- Output in a named format goes through the hardened, fuzzed `ctis/importer` parsers and then through the same record checks as any tool output: CTIS validity, declared outputs and limits.
