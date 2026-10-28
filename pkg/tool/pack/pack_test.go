package pack

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

const passiveTool = `apiVersion: openctem.io/tool/v1
name: plain-http
version: 0.1.0
class: target-scan
tier: T0
consumes: [http_service]
produces: ["finding:misconfiguration"]
permissions:
  network: none
run:
  argv: ["./plain_http.py"]
`

const activeTool = `apiVersion: openctem.io/tool/v1
name: http-title
version: 0.2.0
class: target-scan
tier: T1
implements:
  - capability: probe.http@1
consumes: [http_service]
produces: ["asset:http_service"]
engine:
  name: curl
  license: curl
run:
  argv: ["./http_title.py"]
`

const goodPack = `apiVersion: openctem.io/pack/v1
name: web-basics
version: 1.0.0
publisher: example
license: Apache-2.0
tier: T1
tools:
  - name: plain-http
  - name: http-title
    path: tools/title
engines:
  - name: curl
    version: 8.10.0
    license: curl
    url: https://curl.se/download/curl-8.10.0.tar.gz
    sha256:
      linux/amd64: 9d8439e8b6c9aa7d1e2314817a392e00d5178da3af5652f7475f88868f418f76
      linux/arm64: fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e
platforms: [linux/amd64, linux/arm64]
requires:
  sdk: 0.39.0
  protocol: 1
image:
  base: docker.io/library/python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
`

func writePack(t *testing.T, packYAML string) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		"pack.yaml":                 packYAML,
		"plain-http/tool.yaml":      passiveTool,
		"tools/title/tool.yaml":     activeTool,
		"plain-http/plain_http.py":  "#!/usr/bin/env python3\n",
		"tools/title/http_title.py": "#!/usr/bin/env python3\n",
	}
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestLoadDirGood(t *testing.T) {
	d, err := LoadDir(writePack(t, goodPack))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Tools) != 2 || d.Tools[0].Name != "plain-http" || d.Tools[1].Name != "http-title" {
		t.Fatalf("tools %+v", d.Tools)
	}
	desc := d.Describe()
	if desc.Tier != tool.T1 || !slices.Equal(desc.Capabilities, []string{"probe.http@1"}) {
		t.Fatalf("description %+v", desc)
	}
	if !strings.HasPrefix(desc.Digest, "sha256:") || desc.Tools[1].MinimumTier != tool.T1 {
		t.Fatalf("description %+v", desc)
	}
	if d.Pack.Digest() != desc.Digest {
		t.Fatal("digest differs")
	}
}

// A pack cannot hide an active tool behind a passive label, and cannot
// claim a higher tier than its tools need either: the tier is the truth.
func TestTierMustEqualTools(t *testing.T) {
	_, err := LoadDir(writePack(t, strings.Replace(goodPack, "tier: T1", "tier: T0", 1)))
	assertErr(t, err, "/tier", "need T1 (http-title)")
	_, err = LoadDir(writePack(t, strings.Replace(goodPack, "tier: T1", "tier: T2", 1)))
	assertErr(t, err, "/tier", "need T1")
}

func TestToolsMustMatch(t *testing.T) {
	// A listed tool with no tool.yaml.
	_, err := LoadDir(writePack(t, strings.Replace(goodPack, "path: tools/title", "path: tools/missing", 1)))
	assertErr(t, err, "/tools/1/path", "tools/missing: no such directory")
	// A tool.yaml whose name differs from the listed name.
	p := Pack{}
	if err := json.Unmarshal(mustJSON(t, goodPack), &p); err != nil {
		t.Fatal(err)
	}
	var m tool.Manifest
	m, err = tool.LoadManifest([]byte(passiveTool))
	if err != nil {
		t.Fatal(err)
	}
	other, _ := tool.LoadManifest([]byte(strings.Replace(activeTool, "name: http-title", "name: http-other", 1)))
	err = p.Check([]tool.Manifest{m, other})
	assertErr(t, err, "/tools/1", `no tool named "http-title"`)
	assertErr(t, err, "/tools", `"http-other" is in the pack but not listed`)
}

func TestEngineMustBeListed(t *testing.T) {
	y := goodPack[:strings.Index(goodPack, "engines:")] + goodPack[strings.Index(goodPack, "platforms:"):]
	_, err := LoadDir(writePack(t, y))
	assertErr(t, err, "/engines", `http-title runs the engine "curl"`)
}

func TestSDKMustCoverTools(t *testing.T) {
	root := writePack(t, strings.Replace(goodPack, "sdk: 0.39.0", "sdk: 0.38.0", 1))
	body := activeTool + "sdk:\n  min: 0.39.0\n"
	if err := os.WriteFile(filepath.Join(root, "tools/title/tool.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(root)
	assertErr(t, err, "/requires/sdk", "needs SDK 0.39.0")
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]struct{ from, to, path, msg string }{
		"unknown key":      {"license: Apache-2.0", "license: Apache-2.0\nhomepage: x", "", "unknown key"},
		"bad api version":  {"openctem.io/pack/v1", "openctem.io/pack/v2", "/apiVersion", "must be"},
		"leading v":        {"version: 1.0.0", "version: v1.0.0", "/version", "semantic version"},
		"no publisher":     {"publisher: example", "publisher: Example Inc", "/publisher", "namespace"},
		"no license":       {"license: Apache-2.0", "license: \"\"", "/license", "SPDX"},
		"bad tier":         {"tier: T1", "tier: active", "/tier", "T0 (passive)"},
		"path escapes":     {"path: tools/title", "path: ../title", "/tools/1/path", "inside the pack"},
		"absolute path":    {"path: tools/title", "path: /etc", "/tools/1/path", "inside the pack"},
		"unclean path":     {"path: tools/title", "path: tools//title", "/tools/1/path", "inside the pack"},
		"bad platform":     {"platforms: [linux/amd64, linux/arm64]", "platforms: [linux/amd64, windows/amd64]", "/platforms/1", "not one of"},
		"sha missing arch": {"      linux/arm64: fd7b123c1dfbc3d69f19f524e4eebcd6ec06b9a6cbd56813c76f11645197331e\n", "", "/engines/0/sha256", "no sha256 for linux/arm64"},
		"http engine url":  {"https://curl.se", "http://curl.se", "/engines/0/url", "https"},
		"newer sdk":        {"sdk: 0.39.0", "sdk: 99.0.0", "/requires/sdk", "needs SDK 99.0.0; this is"},
		"protocol 2":       {"protocol: 1", "protocol: 2", "/requires/protocol", "must be 1"},
		"base by tag":      {"python@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1", "python:3.12-slim", "/image/base", "pinned by digest"},
		"duplicate tool":   {"  - name: http-title", "  - name: plain-http", "/tools/1/name", "listed twice"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			y := strings.Replace(goodPack, c.from, c.to, 1)
			if y == goodPack {
				t.Fatalf("replacement %q not found", c.from)
			}
			_, err := Load([]byte(y))
			assertErr(t, err, c.path, c.msg)
		})
	}
}

func TestLoadRefusesShape(t *testing.T) {
	for _, in := range []string{"- a\n", "a: 1\n---\nb: 2\n", strings.Repeat("#", MaxManifestBytes+1)} {
		if _, err := Load([]byte(in)); err == nil {
			t.Errorf("%.20q accepted", in)
		}
	}
}

func TestSymlinkedToolRefused(t *testing.T) {
	root := writePack(t, goodPack)
	if err := os.Rename(filepath.Join(root, "tools/title"), filepath.Join(root, "real")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "tools/title")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadDir(root)
	assertErr(t, err, "/tools/1/path", "symbolic link")
}

// The JSON Schema names exactly the pack's keys.
func TestSchemaMatchesTypes(t *testing.T) {
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(tool.PackJSONSchema(), &schema); err != nil {
		t.Fatal(err)
	}
	if got, want := keys(schema.Properties), jsonKeys(reflect.TypeFor[Pack]()); !slices.Equal(got, want) {
		t.Fatalf("schema keys %v, Pack keys %v", got, want)
	}
	sub := func(raw json.RawMessage, items bool) []string {
		var p struct {
			Properties map[string]json.RawMessage `json:"properties"`
			Items      struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"items"`
		}
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatal(err)
		}
		if items {
			return keys(p.Items.Properties)
		}
		return keys(p.Properties)
	}
	for name, c := range map[string]struct {
		typ   reflect.Type
		items bool
	}{
		"tools": {reflect.TypeFor[ToolRef](), true}, "engines": {reflect.TypeFor[Engine](), true},
		"requires": {reflect.TypeFor[Requires](), false}, "image": {reflect.TypeFor[Image](), false},
	} {
		if got, want := sub(schema.Properties[name], c.items), jsonKeys(c.typ); !slices.Equal(got, want) {
			t.Errorf("%s: schema keys %v, Go keys %v", name, got, want)
		}
	}
	var req []string
	for _, f := range reflect.VisibleFields(reflect.TypeFor[Pack]()) {
		if tag := f.Tag.Get("json"); !strings.Contains(tag, "omitempty") {
			name, _, _ := strings.Cut(tag, ",")
			req = append(req, name)
		}
	}
	sort.Strings(req)
	got := slices.Clone(schema.Required)
	sort.Strings(got)
	if !slices.Equal(got, req) {
		t.Errorf("schema required %v, Go required %v", got, req)
	}
}

func assertErr(t *testing.T, err error, path, msg string) {
	t.Helper()
	var errs Errors
	if !errors.As(err, &errs) {
		t.Fatalf("want pack errors, got %v", err)
	}
	for _, e := range errs {
		if e.Path == path && strings.Contains(e.Message, msg) {
			return
		}
	}
	t.Fatalf("no error at %q containing %q in %v", path, msg, err)
}

func mustJSON(t *testing.T, y string) []byte {
	t.Helper()
	p, err := Load([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func jsonKeys(t reflect.Type) []string {
	var out []string
	for i := range t.NumField() {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if name != "" && name != "-" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
