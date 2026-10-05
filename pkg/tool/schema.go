package tool

import (
	_ "embed"
	"slices"
)

//go:embed schema/tool.v1.schema.json
var manifestSchema []byte

//go:embed schema/adapter.v1.schema.json
var adapterSchema []byte

// AdapterProtocolJSONSchema returns the JSON Schema of one adapter
// protocol v1 message, for implementations in other languages.
func AdapterProtocolJSONSchema() []byte { return slices.Clone(adapterSchema) }

// ManifestJSONSchema returns the JSON Schema of tool.yaml (draft 2020-12),
// for editors and for implementations in other languages. Validate checks
// more than the schema can express (class against permissions, placeholders
// against the config schema, no secrets in config).
func ManifestJSONSchema() []byte { return slices.Clone(manifestSchema) }
