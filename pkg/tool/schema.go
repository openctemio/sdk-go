package tool

import (
	_ "embed"
	"slices"
)

//go:embed schema/tool.v1.schema.json
var manifestSchema []byte

// ManifestJSONSchema returns the JSON Schema of tool.yaml (draft 2020-12),
// for editors and for implementations in other languages. Validate checks
// more than the schema can express (class against permissions, placeholders
// against the config schema, no secrets in config).
func ManifestJSONSchema() []byte { return slices.Clone(manifestSchema) }
