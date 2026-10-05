### Fixed

- **semgrep: a partially parsed file no longer drops every finding.**
  semgrep emits `errors[].type` as a string or an array
  (`["PartialParsing", [...]]`); `SemgrepError.Type` was a string, so
  `json.Unmarshal` failed for the whole document and the adapter returned no
  findings at all. `SemgrepError` now decodes every shape and keeps the kind
  name in `Type` (still a string, e.g. `"PartialParsing"`).
