### Added: the file importer as a parser-class tool

- `pkg/importtool` (Beta): a tool of the tool contract, class `parser`, network `none`, workdir only. It converts the task's input files (Nessus v2 XML, Qualys detection XML with its KnowledgeBase, DefectDojo Generic Findings JSON, CycloneDX, SPDX, osv-scanner results, CSAF, OpenVEX) to CTIS with the `ctis/importer` package and emits them through the runtime's checks. Problems are logged with their line numbers; the statements of VEX documents go to the artifact `vex-statements.json`, never into findings.
- `testkit.Options.Files` writes files into the task directory before a run, as the runtime places a parser's inputs.

### Security

- An input must be a regular file inside the task directory: absolute paths, `..`, links and directories are refused, and so are archives (the runtime extracts them). Files are parsed with the importer's hostile-input limits (no XML entities or external resources, size, depth and record caps).
