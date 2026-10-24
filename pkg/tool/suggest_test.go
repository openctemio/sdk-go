package tool

import (
	"strings"
	"testing"
)

func TestLevenshteinAndNearest(t *testing.T) {
	if d := levenshtein("kitten", "sitting"); d != 3 {
		t.Fatalf("distance %d", d)
	}
	if d := levenshtein("", "abc"); d != 3 {
		t.Fatalf("distance %d", d)
	}
	got := nearest("misconfig", []string{"vulnerability", "secret", "misconfiguration"}, 2)
	if len(got) != 1 || got[0] != "misconfiguration" {
		t.Fatalf("got %v", got)
	}
	if got := nearest("zzzzzz", []string{"vulnerability", "secret"}, 2); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestEchoIsQuotedAndBounded(t *testing.T) {
	e := echo("a\x1b[31m\nb" + strings.Repeat("x", 200))
	if strings.ContainsAny(e, "\x1b\n") {
		t.Fatalf("control character echoed: %q", e)
	}
	if len(e) > maxEcho+16 {
		t.Fatalf("not truncated: %d bytes", len(e))
	}
}

// Messages of the manifest loader name the fix. Each case is one input an
// author really typed and substrings its message must carry.
func TestManifestErrorsNameTheFix(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want []string
	}{
		{"produces typo", patch(baseYAML, "produces", "produces: [\"finding:misconfig\"]"),
			[]string{"/produces/0:", `unknown CTIS finding type "misconfig"`, `did you mean "misconfiguration"?`, "allowed: vulnerability"}},
		{"consumes url", patch(baseYAML, "consumes", "consumes: [url]"),
			[]string{"/consumes/0:", `unknown CTIS asset type "url"`, "http_service", "discovered_url", "website"}},
		{"consumes ip", patch(baseYAML, "consumes", "consumes: [ip]"), []string{"use ip_address"}},
		{"consumes port", patch(baseYAML, "consumes", "consumes: [port]"), []string{"use open_port"}},
		{"consumes repo", patch(baseYAML, "consumes", "consumes: [repo]"), []string{"use repository"}},
		{"consumes image", patch(baseYAML, "consumes", "consumes: [image]"), []string{"use container"}},
		{"asset typo", patch(baseYAML, "produces", "produces: [\"asset:subdomian\"]"), []string{`did you mean "subdomain"?`}},
		{"unknown asset without hint", patch(baseYAML, "consumes", "consumes: [qqqqqqqqqqqq]"),
			[]string{`unknown CTIS asset type "qqqqqqqqqqqq"`}},
		{"top-level misplaced timeout", patch(baseYAML, "class", "class: target-scan\ntimeout: 10m"),
			[]string{"/timeout: unknown key; did you mean /resources/timeout?"}},
		{"misplaced argv", patch(baseYAML, "class", "class: target-scan\nargv: [x]"),
			[]string{"/argv: unknown key; did you mean /run/argv?"}},
		{"misplaced capability", patch(baseYAML, "class", "class: target-scan\ncapability: scan.ports@1"),
			[]string{"/implements/0/capability"}},
		{"misspelled top-level key", patch(baseYAML, "class", "class: target-scan\ndescripton: x"),
			[]string{"/descripton: unknown key; did you mean /description?"}},
		{"nested unknown key", patch(baseYAML, "resources", "resources: {cpu: 1, timout: 20m}"),
			[]string{"/resources/timout: unknown key; did you mean /resources/timeout?"}},
		{"unknown key without a suggestion", patch(baseYAML, "class", "class: target-scan\nqqqqqqq: 1"),
			[]string{"/qqqqqqq: unknown key"}},
		{"unknown key under a map of structs", patch(portScanYAML, "      rate", "      rate: {key: rate, scale: 2}"),
			[]string{"/params/rate/scale: unknown key"}},
		{"version number", patch(baseYAML, "version", "version: 1.0"),
			[]string{"/version: must be a string; quote it", `"1.0.0"`}},
		{"name number", patch(baseYAML, "name", "name: 12"),
			[]string{"/name: must be a string; quote it"}},
		{"nested type", patch(baseYAML, "resources", "resources: {cpu: fast}"),
			[]string{"/resources/cpu: must be a number"}},
		{"object expected", patch(baseYAML, "permissions", "permissions: [a]"),
			[]string{"/permissions: must be an object"}},
		{"array expected", patch(baseYAML, "produces", "produces: finding:vulnerability"),
			[]string{"/produces: must be an array"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest([]byte(tc.yaml))
			if err == nil {
				t.Fatal("want an error")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("want %q in %v", w, err)
				}
			}
			if strings.Contains(err.Error(), "Go struct") || strings.Contains(err.Error(), "json:") {
				t.Errorf("Go-level wording leaked: %v", err)
			}
		})
	}
}

func TestUnknownCapabilityMessage(t *testing.T) {
	if m := unknownCapabilityMessage("scan.ports@2"); !strings.Contains(m, "scan.ports has major 1, not 2") {
		t.Errorf("majors: %s", m)
	}
	if m := unknownCapabilityMessage("scan.prots@1"); !strings.Contains(m, "did you mean scan.ports@1?") {
		t.Errorf("nearest: %s", m)
	}
	if m := unknownCapabilityMessage("qqqq.zzzz@1"); !strings.Contains(m, "docs/capabilities.md") {
		t.Errorf("docs pointer: %s", m)
	}
	if m := unknownCapabilityMessage("check.headers@1"); !strings.Contains(m, "is not in the capability taxonomy") {
		t.Errorf("message: %s", m)
	}
}

func TestHostileKeyIsEscaped(t *testing.T) {
	_, err := LoadManifest([]byte(patch(baseYAML, "class", "class: target-scan\n\"a\\e[31mb\": 1")))
	if err == nil || strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("escape leaked: %q", err)
	}
}
