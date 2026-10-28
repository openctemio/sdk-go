// Package contract holds the openctem.analyze/v1 JSON Schemas an analyst
// worker validates against: the job it receives, the result it returns, the
// typed suggestions and the output schema of each kind.
//
// The platform (openctem api/pkg/sensorproto/analyze) is the source of these
// files; this package carries byte-identical copies, pinned by digest in
// contract_test.go, so a change on either side is a deliberate, reviewed
// update and never silent drift. Design: openctem
// api/docs/rfcs/RFC-131-ai-analysis.md and RFC-133-ai-analyst-harness.md.
//
// Stability: Experimental (docs/STABILITY.md).
package contract

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// Contract identifiers.
const (
	Job    = "openctem.analyze/v1"
	Result = "openctem.analyze.result/v1"
)

// Schema ids (the $id of each embedded schema).
const (
	SchemaJob               = "https://openctem.io/schemas/analyze/job/v1.json"
	SchemaResult            = "https://openctem.io/schemas/analyze/result/v1.json"
	SchemaSuggestion        = "https://openctem.io/schemas/analyze/suggestion/v1.json"
	SchemaOutputTriage      = "https://openctem.io/schemas/analyze/output/triage/v1.json"
	SchemaOutputRemediation = "https://openctem.io/schemas/analyze/output/remediation/v1.json"
	SchemaOutputSummary     = "https://openctem.io/schemas/analyze/output/summary/v1.json"
)

// Output schema names, as a job names them in output_schema.
const (
	OutputTriageV1      = "openctem.ai.triage/v1"
	OutputRemediationV1 = "openctem.ai.remediation/v1"
	OutputSummaryV1     = "openctem.ai.summary/v1"
)

// MaxDocumentBytes bounds a job, result or model output document.
const MaxDocumentBytes = 256 << 10

//go:embed schemas/*.json
var schemaFS embed.FS

var schemaFiles = map[string]string{
	SchemaJob:               "schemas/job.v1.schema.json",
	SchemaResult:            "schemas/result.v1.schema.json",
	SchemaSuggestion:        "schemas/suggestion.v1.schema.json",
	SchemaOutputTriage:      "schemas/output.triage.v1.schema.json",
	SchemaOutputRemediation: "schemas/output.remediation.v1.schema.json",
	SchemaOutputSummary:     "schemas/output.summary.v1.schema.json",
}

var outputSchemas = map[string]string{
	OutputTriageV1:      SchemaOutputTriage,
	OutputRemediationV1: SchemaOutputRemediation,
	OutputSummaryV1:     SchemaOutputSummary,
}

// OutputSchemaID maps an output schema name (openctem.ai.triage/v1) to the
// schema id it is validated against.
func OutputSchemaID(name string) (string, bool) {
	id, ok := outputSchemas[name]
	return id, ok
}

// SchemaJSON returns the raw bytes of one embedded schema (nil if unknown),
// for prompts and for implementations in other languages.
func SchemaJSON(id string) []byte {
	f, ok := schemaFiles[id]
	if !ok {
		return nil
	}
	b, err := schemaFS.ReadFile(f)
	if err != nil {
		return nil
	}
	return b
}

// ErrInvalid matches every validation failure of this package (errors.Is).
var ErrInvalid = errors.New("analyze_contract_invalid")

// InvalidError is a document that does not satisfy its schema. Location names
// the first failing place; the error never echoes document content, so it is
// safe to return to a model or to log.
type InvalidError struct {
	Schema   string
	Location string
}

func (e *InvalidError) Error() string {
	return "invalid " + e.Schema + " at " + e.Location
}

// Is makes errors.Is(err, ErrInvalid) true.
func (e *InvalidError) Is(target error) bool { return target == ErrInvalid }

var (
	compileOnce sync.Once
	compiled    map[string]*jsonschema.Schema
	compileErr  error
)

func schemas() (map[string]*jsonschema.Schema, error) {
	compileOnce.Do(func() {
		c := jsonschema.NewCompiler()
		c.DefaultDraft(jsonschema.Draft2020)
		for id, f := range schemaFiles {
			raw, err := schemaFS.ReadFile(f)
			if err != nil {
				compileErr = err
				return
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				compileErr = fmt.Errorf("schema %s: %w", f, err)
				return
			}
			if err := c.AddResource(id, doc); err != nil {
				compileErr = err
				return
			}
		}
		out := make(map[string]*jsonschema.Schema, len(schemaFiles))
		for id := range schemaFiles {
			s, err := c.Compile(id)
			if err != nil {
				compileErr = err
				return
			}
			out[id] = s
		}
		compiled = out
	})
	return compiled, compileErr
}

// Validate checks doc against the schema with the given id.
func Validate(schemaID string, doc []byte) error {
	all, err := schemas()
	if err != nil {
		return err
	}
	s, ok := all[schemaID]
	if !ok {
		return &InvalidError{Schema: schemaID, Location: "unknown schema"}
	}
	if len(doc) > MaxDocumentBytes {
		return &InvalidError{Schema: schemaID, Location: "document too large"}
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(doc))
	if err != nil {
		return &InvalidError{Schema: schemaID, Location: "not JSON"}
	}
	if err := s.Validate(v); err != nil {
		return &InvalidError{Schema: schemaID, Location: location(err)}
	}
	return nil
}

// location returns the instance location of the deepest cause, as a JSON
// pointer, without the offending value.
func location(err error) string {
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return "/"
	}
	for len(ve.Causes) > 0 {
		ve = ve.Causes[0]
	}
	if len(ve.InstanceLocation) == 0 {
		return "/"
	}
	return "/" + strings.Join(ve.InstanceLocation, "/")
}

// Evidence cites a bundle field ("bundle:<field>") or a tool output
// ("tool:<n>").
type Evidence struct {
	Ref   string `json:"ref"`
	Quote string `json:"quote,omitempty"`
}

// Suggestion is one typed suggestion (suggestion/v1).
type Suggestion struct {
	Kind       string          `json:"kind"`
	Payload    json.RawMessage `json:"payload"`
	Confidence float64         `json:"confidence"`
	Evidence   []Evidence      `json:"evidence"`
}

// Output is a model's final answer for one kind (output/<kind>/v1).
type Output struct {
	Suggestions []Suggestion `json:"suggestions"`
}

// ParseOutput validates raw against the named output schema and decodes it.
func ParseOutput(outputSchema string, raw []byte) (*Output, error) {
	id, ok := OutputSchemaID(outputSchema)
	if !ok {
		return nil, &InvalidError{Schema: outputSchema, Location: "unknown output schema"}
	}
	if err := Validate(id, raw); err != nil {
		return nil, err
	}
	var out Output
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return nil, &InvalidError{Schema: outputSchema, Location: "decode"}
	}
	return &out, nil
}
