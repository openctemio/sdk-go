### Upgrade notes

- Replace `ctis.FromSARIF(data, &ctis.ConvertOptions{...})` with `(&core.SARIFParser{}).Parse(ctx, data, &core.ParseOptions{...})`: the option names are the same (`AssetType`, `AssetValue`, `AssetID`, `Branch`, `CommitSHA`, `BranchInfo`, `DefaultConfidence`, `ToolType`). Code that needs the bare module converter imports `github.com/openctemio/ctis` directly.

### Removed: `ctis.FromSARIF` and the SARIF kind helpers

- `pkg/ctis.FromSARIF`, `NormalizeSARIFKind` and `NormalizeSARIFBaselineState` are removed, and the module's bare `FromSARIF` is no longer re-exported. Convert SARIF with `core.SARIFParser` (same asset rule, same options), which runs on `github.com/openctemio/ctis/importer`. `SARIFLog` and `SARIFRun` stay.

### Changed: SARIF converts through the ctis importer

- `core.SARIFParser` and the tool host (`pkg/sensorkit/toolhost`, `output.format: sarif`) convert SARIF with `github.com/openctemio/ctis/importer`, the conversion the platform's import and CI endpoints use. The asset rule is unchanged (options, then branch info, then `versionControlProvenance`, then the CI job; findings with none of them are `ctis.ErrNoAssetForFindings`), and so are the findings: `ToolType` and `DefaultConfidence` still apply (ctis#34), and `BranchInfo` is still the report branch.
- Differences, all additions or fixes: the input gets the importer's hostile-input limits; a user and password in a `versionControlProvenance` repository URL are removed from the asset value; the asset carries a name and its branch and commit properties, and the report its scope; a result with neither a message nor a rule is skipped with an issue; `DefaultConfidence` 0 now means 90 (it used to give findings confidence 0).
