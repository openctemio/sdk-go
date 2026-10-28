package contract

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// The platform owns these schemas (openctem api/pkg/sensorproto/analyze/schemas).
// A digest change here must be the same reviewed change as on the platform:
// copy the files byte for byte and update the pins together.
var pinned = map[string]string{
	"schemas/job.v1.schema.json":                "3894b3d908af02c4e917bc8c2ca61bd450bedaa77577e7dfeb45ef817760b460",
	"schemas/output.remediation.v1.schema.json": "41c76b651e57f7a21ae7d97d49fe5d47848778ec6c8167304235512891dc9c77",
	"schemas/output.summary.v1.schema.json":     "21700674c199d8f2e89de1de1b04e2b2aa613b9c1e23e6191fb9bba38fd44a2e",
	"schemas/output.triage.v1.schema.json":      "d738e656d7babd8270c36ea8efa38536af15499acb495b745aaf393355647c5a",
	"schemas/result.v1.schema.json":             "c48ac541c2e0c78fa6956e8e3fd08942226608eb27841d44c7ecd51e1171f77b",
	"schemas/suggestion.v1.schema.json":         "0a78db9c246af5120938281b8a5d7d2db175fff54dfa3876538d36ef7a77b7c4",
}

func TestSchemasArePinnedCopiesOfThePlatformContract(t *testing.T) {
	entries, err := schemaFS.ReadDir("schemas")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(pinned) {
		t.Fatalf("%d schema files embedded, %d pinned", len(entries), len(pinned))
	}
	for f, want := range pinned {
		b, err := schemaFS.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != want {
			t.Errorf("%s drifted from the platform copy: sha256 %s, pinned %s", f, got, want)
		}
	}
}

const validTriage = `{"suggestions":[
 {"kind":"verdict","payload":{"verdict":"true_positive","reason":"The payload is reflected unencoded."},"confidence":0.8,"evidence":[{"ref":"tool:1","quote":"<script>"}]},
 {"kind":"summary","payload":{"text":"Reflected XSS on the search page."},"confidence":0.9,"evidence":[{"ref":"bundle:finding.title"}]}
]}`

func TestParseOutputAcceptsAValidTriage(t *testing.T) {
	out, err := ParseOutput(OutputTriageV1, []byte(validTriage))
	if err != nil {
		t.Fatalf("valid output refused: %v", err)
	}
	if len(out.Suggestions) != 2 || out.Suggestions[0].Kind != "verdict" {
		t.Fatalf("decoded %+v", out)
	}
}

func TestParseOutputRefusesOutsideTheClosedSchema(t *testing.T) {
	cases := map[string]string{
		"extra top-level key":   `{"suggestions":[],"approve":true}`,
		"unknown verdict":       `{"suggestions":[{"kind":"verdict","payload":{"verdict":"closed","reason":"r"},"confidence":0.5,"evidence":[]}]}`,
		"evidence to elsewhere": `{"suggestions":[{"kind":"summary","payload":{"text":"t"},"confidence":0.5,"evidence":[{"ref":"https://attacker.example/x"}]}]}`,
		"confidence above one":  `{"suggestions":[{"kind":"summary","payload":{"text":"t"},"confidence":1.5,"evidence":[]}]}`,
		"not json":              `Sure! Here is the answer.`,
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := ParseOutput(OutputTriageV1, []byte(doc))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("want ErrInvalid, got %v", err)
			}
			if strings.Contains(err.Error(), "attacker") || strings.Contains(err.Error(), "Sure") {
				t.Fatalf("error echoes document content: %v", err)
			}
		})
	}
}

func TestParseOutputRefusesAnUnknownSchemaName(t *testing.T) {
	if _, err := ParseOutput("openctem.ai.anything/v9", []byte(`{}`)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

func TestEverySchemaCompiles(t *testing.T) {
	for id := range schemaFiles {
		if SchemaJSON(id) == nil {
			t.Fatalf("%s not embedded", id)
		}
	}
	if _, err := schemas(); err != nil {
		t.Fatal(err)
	}
}
