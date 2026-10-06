// Package ctis is the SDK's name for the CTIS data model
// (github.com/openctemio/ctis).
//
// It holds no copy of the model. Every exported type, constant and function
// of the ctis module is re-exported here (zz_generated_aliases.go, written by
// internal/genalias from the version go.mod requires): types are aliases, so
// a ctis.Report from this package and from the module are the same type and
// mix freely. Bumping the CTIS version is a go.mod change plus
// `go generate ./pkg/ctis`; CI fails when the generated file is stale.
//
// What the SDK adds on top of the module:
//
//   - SARIFLog / SARIFRun: the module's SARIF root types plus
//     versionControlProvenance (SARIFRun.Repository).
//   - CheckFindingAssets / ErrNoAssetForFindings: every finding needs an
//     asset of its own report (the rule protocol v2 ingest enforces).
//
// SARIF is converted by core.SARIFParser, through the module's importer
// package; the module's bare FromSARIF is not re-exported.
//
// Stability: Stable (docs/STABILITY.md).
package ctis

//go:generate go run ./internal/genalias zz_generated_aliases.go
