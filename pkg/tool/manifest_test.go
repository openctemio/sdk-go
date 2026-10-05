package tool

import (
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

const baseYAML = `apiVersion: openctem.io/tool/v1
name: acme-lint
version: 1.4.0
class: target-scan
modes: [runner, daemon]
tier: T0
capabilities: [code.sast]
consumes: [repository]
produces: [finding:vulnerability, finding:misconfiguration]
config:
  type: object
  additionalProperties: false
  properties:
    ruleset: {type: string, enum: [default, strict], default: default}
    depth: {type: integer, minimum: 1, maximum: 10, default: 3}
    tags: {type: array, items: {type: string}, maxItems: 8}
permissions: {network: none, filesystem: scan-roots-read-only}
resources: {cpu: 1, memory: 1Gi, timeout: 20m}
run:
  profile: exec
  argv: [acme-lint, --format, sarif, --ruleset, "{{config.ruleset}}", "{{target.value}}"]
  output: {format: sarif, from: stdout}
  exit_codes: {"0": ok, "1": ok, "2": tool_error}
protocol: {min: 1}
`

// patch replaces the line starting with key, with the indented block
// under a top-level key (or appends the line).
func patch(yaml, key, line string) string {
	lines := strings.Split(yaml, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, key+":") {
			continue
		}
		end := i + 1
		if !strings.HasPrefix(key, " ") {
			for end < len(lines) && strings.HasPrefix(lines[end], " ") {
				end++
			}
		}
		var repl []string
		if line != "" {
			repl = []string{line}
		}
		out := append(append(append([]string{}, lines[:i]...), repl...), lines[end:]...)
		return strings.Join(out, "\n")
	}
	return yaml + line + "\n"
}

func TestLoadManifestValid(t *testing.T) {
	m, err := LoadManifest([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	if m.Name != "acme-lint" || m.Class != TargetScan || m.Resources.Memory != 1<<30 ||
		time.Duration(m.Resources.Timeout) != 20*time.Minute || m.Run.Profile != ProfileExec {
		t.Fatalf("decoded %+v", m)
	}
	if !m.Declares(KindFinding, "vulnerability") || m.Declares(KindAsset, "domain") || m.Declares(KindDependency, "") {
		t.Fatal("Declares")
	}
	if s, err := m.ConfigSchema(); err != nil || s.Property("ruleset") == nil {
		t.Fatalf("config schema: %v", err)
	}
}

func TestManifestCases(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		errPath string // "" = valid
	}{
		{"valid", baseYAML, ""},
		{"json form", `{"apiVersion":"openctem.io/tool/v1","name":"j-tool","version":"0.1.0","class":"parser","tier":"T0","consumes":["file:application/sarif+json"],"produces":["finding:vulnerability"]}`, ""},
		{"connector", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\npermissions: {network: vendor, vendor_hosts: [api.example.com, \"api.example.com:8443\"], credentials: [{name: api_key, kind: api_key, required: true}]}\n", ""},
		{"connector vendor host from config", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\nconfig: {type: object, additionalProperties: false, properties: {base_url: {type: string, format: uri}}}\npermissions: {vendor_hosts: [\"${config.base_url}\"]}\n", ""},
		{"enricher", "apiVersion: openctem.io/tool/v1\nname: enr\nversion: 1.0.0\nclass: enricher\ntier: T0\nconsumes: [finding:vulnerability]\nproduces: [finding:vulnerability]\n", ""},
		{"adapter run", patch(baseYAML, "run", "run: {argv: [python3, dotenv.py]}"), ""},
		{"wrong apiVersion", patch(baseYAML, "apiVersion", "apiVersion: openctem.io/tool/v2"), "/apiVersion"},
		{"unknown key", baseYAML + "extra: 1\n", "unknown field"},
		{"unknown nested key", patch(baseYAML, "permissions", "permissions: {network: none, shell: true}"), "unknown field"},
		{"duplicate key", baseYAML + "name: other\n", "already defined"},
		{"two documents", baseYAML + "---\nname: x\n", "more than one"},
		{"not a mapping", "- a\n- b\n", "not a mapping"},
		{"bad name", patch(baseYAML, "name", "name: Acme_Lint"), "/name"},
		{"bad version", patch(baseYAML, "version", "version: latest"), "/version"},
		{"bad class", patch(baseYAML, "class", "class: scanner"), "/class"},
		{"bad mode", patch(baseYAML, "modes", "modes: [daemon, cron]"), "/modes/1"},
		{"duplicate mode", patch(baseYAML, "modes", "modes: [daemon, daemon]"), "/modes/1"},
		{"bad tier", patch(baseYAML, "tier", "tier: T3"), "/tier"},
		{"T2 on a parser", "apiVersion: openctem.io/tool/v1\nname: p\nversion: 1.0.0\nclass: parser\ntier: T2\nconsumes: [file:text/plain]\nproduces: [finding:secret]\n", "/tier"},
		{"bad capability", patch(baseYAML, "capabilities", "capabilities: [\"Code SAST\"]"), "/capabilities/0"},
		{"unknown consumed asset", patch(baseYAML, "consumes", "consumes: [spaceship]"), "/consumes/0"},
		{"file input on a target scan", patch(baseYAML, "consumes", "consumes: [file:text/plain]"), "/consumes/0"},
		{"parser consuming an asset", "apiVersion: openctem.io/tool/v1\nname: p\nversion: 1.0.0\nclass: parser\ntier: T0\nconsumes: [repository]\nproduces: [finding:secret]\n", "/consumes/0"},
		{"no produces", patch(baseYAML, "produces", ""), "/produces"},
		{"unknown produced type", patch(baseYAML, "produces", "produces: [finding:rumor]"), "/produces/0"},
		{"bad produce kind", patch(baseYAML, "produces", "produces: [report]"), "/produces/0"},
		{"enricher creating assets", "apiVersion: openctem.io/tool/v1\nname: enr\nversion: 1.0.0\nclass: enricher\ntier: T0\nconsumes: [finding:vulnerability]\nproduces: [asset:domain]\n", "/produces/0"},
		{"secret in config (sensitive)", patch(baseYAML, "config", "config: {type: object, additionalProperties: false, properties: {key: {type: string, x-octm-sensitive: true}}}"), "/config/properties/key"},
		{"secret in config (name)", patch(baseYAML, "config", "config: {type: object, additionalProperties: false, properties: {api_token: {type: string}}}"), "/config/properties/api_token"},
		{"config outside the subset", patch(baseYAML, "config", "config: {type: object, additionalProperties: false, properties: {a: {oneOf: [{type: string}]}}}"), "/config"},
		{"targets network on a parser", "apiVersion: openctem.io/tool/v1\nname: p\nversion: 1.0.0\nclass: parser\ntier: T0\nconsumes: [file:text/plain]\nproduces: [finding:secret]\npermissions: {network: targets}\n", "/permissions/network"},
		{"connector without vendor hosts", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\n", "/permissions/vendor_hosts"},
		{"connector with targets network", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\npermissions: {network: targets}\n", "/permissions/network"},
		{"vendor host from a missing key", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\npermissions: {vendor_hosts: [\"${config.nope}\"]}\n", "/permissions/vendor_hosts/0"},
		{"bad vendor host", "apiVersion: openctem.io/tool/v1\nname: feed\nversion: 1.0.0\nclass: connector\ntier: T0\nproduces: [asset:domain]\npermissions: {vendor_hosts: [\"http://x/\"]}\n", "/permissions/vendor_hosts/0"},
		{"bad credential kind", patch(baseYAML, "permissions", "permissions: {network: none, credentials: [{name: k, kind: magic}]}"), "/permissions/credentials/0/kind"},
		{"duplicate credential", patch(patch(baseYAML, "run", "run: {argv: [x]}"), "permissions", "permissions: {network: none, credentials: [{name: k, kind: token}, {name: k, kind: token}]}"), "/permissions/credentials/1/name"},
		{"capability not allowed", patch(baseYAML, "permissions", "permissions: {network: none, linux_caps: [SYS_ADMIN]}"), "/permissions/linux_caps/0"},
		{"resources out of range", patch(baseYAML, "resources", "resources: {memory: 128Gi, timeout: 48h, cost: 99}"), "/resources/memory"},
		{"bad size", patch(baseYAML, "resources", "resources: {memory: lots}"), "invalid size"},
		{"shell in argv", patch(baseYAML, "  argv", "  argv: [/bin/sh, -c, \"acme {{target.value}}\"]"), "/run/argv/0"},
		{"env launcher in argv", patch(baseYAML, "  argv", "  argv: [env, acme-lint]"), "/run/argv/0"},
		{"unknown placeholder", patch(baseYAML, "  argv", "  argv: [acme-lint, \"{{env.HOME}}\"]"), "/run/argv/1"},
		{"placeholder of a list key", patch(baseYAML, "  argv", "  argv: [acme-lint, \"{{config.tags}}\"]"), "/run/argv/1"},
		{"placeholder of a missing key", patch(baseYAML, "  argv", "  argv: [acme-lint, \"{{config.nope}}\"]"), "/run/argv/1"},
		{"placeholder as program", patch(baseYAML, "  argv", "  argv: [\"{{config.ruleset}}\"]"), "/run/argv/0"},
		{"unbalanced braces", patch(baseYAML, "  argv", "  argv: [acme-lint, \"{{target.value}\"]"), "/run/argv/1"},
		{"exec with credentials", patch(baseYAML, "permissions", "permissions: {network: none, credentials: [{name: k, kind: token}]}"), "/permissions/credentials"},
		{"exec without output", patch(baseYAML, "  output", ""), "/run/output"},
		{"file output without placeholder", patch(baseYAML, "  output", "  output: {format: sarif, from: file}"), "/run/output/from"},
		{"bad exit outcome", patch(baseYAML, "  exit_codes", "  exit_codes: {\"0\": great}"), "/run/exit_codes/0"},
		{"bad exit code", patch(baseYAML, "  exit_codes", "  exit_codes: {\"300\": ok}"), "/run/exit_codes/300"},
		{"protocol too new", patch(baseYAML, "protocol", "protocol: {min: 2}"), "/protocol/min"},
		{"selftest escaping", baseYAML + "selftest: [{name: a, task: ../../etc/passwd, expect: out.json}]\n", "/selftest/0/task"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadManifest([]byte(tc.yaml))
			if tc.errPath == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want an error at %s", tc.errPath)
			}
			if !strings.Contains(err.Error(), tc.errPath) {
				t.Fatalf("want an error at %s, got %v", tc.errPath, err)
			}
		})
	}
	if len(cases) < 40 {
		t.Fatalf("only %d cases", len(cases))
	}
}

func TestManifestTooLarge(t *testing.T) {
	big := baseYAML + "description: \"" + strings.Repeat("a", MaxManifestBytes) + "\"\n"
	if _, err := LoadManifest([]byte(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
}

func TestManifestErrorsListEverything(t *testing.T) {
	bad := patch(patch(baseYAML, "name", "name: X"), "tier", "tier: T9")
	_, err := LoadManifest([]byte(bad))
	var me ManifestErrors
	if !errors.As(err, &me) || len(me) < 2 {
		t.Fatalf("want every problem, got %v", err)
	}
}

func TestDigestIsCanonical(t *testing.T) {
	m1, err := LoadManifest([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	// The same manifest, keys in another order and as JSON.
	js, _ := json.Marshal(m1)
	var generic map[string]any
	_ = json.Unmarshal(js, &generic)
	m2, err := LoadManifest(js)
	if err != nil {
		t.Fatal(err)
	}
	if m1.Digest() != m2.Digest() || !strings.HasPrefix(m1.Digest(), "sha256:") {
		t.Fatalf("digests differ: %s %s", m1.Digest(), m2.Digest())
	}
	m3 := m1
	m3.Permissions.Network = NetTargets
	if m3.Digest() == m1.Digest() {
		t.Fatal("a permission change must change the digest")
	}
	// A Go manifest without defaults digests like its normalized form.
	g := Manifest{Name: "g", Version: "1.0.0", Class: Parser, Tier: T0, Consumes: []string{"file:text/plain"}, Produces: []string{"finding:secret"}}
	if g.Digest() != g.Normalized().Digest() {
		t.Fatal("defaults must not change the digest")
	}
}

// The JSON Schema names exactly the manifest's keys and enums.
func TestManifestJSONSchemaMatchesTypes(t *testing.T) {
	var schema struct {
		Required   []string                   `json:"required"`
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(ManifestJSONSchema(), &schema); err != nil {
		t.Fatal(err)
	}
	if got, want := sortedKeys(schema.Properties), jsonKeys(reflect.TypeFor[Manifest]()); !slices.Equal(got, want) {
		t.Fatalf("schema keys %v, Manifest keys %v", got, want)
	}
	sub := func(name string) map[string]json.RawMessage {
		var p struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(schema.Properties[name], &p); err != nil {
			t.Fatal(err)
		}
		return p.Properties
	}
	for name, typ := range map[string]reflect.Type{
		"permissions": reflect.TypeFor[Permissions](), "resources": reflect.TypeFor[Resources](),
		"protocol": reflect.TypeFor[Range](), "run": reflect.TypeFor[RunSpec](),
	} {
		if got, want := sortedKeys(sub(name)), jsonKeys(typ); !slices.Equal(got, want) {
			t.Errorf("%s: schema keys %v, Go keys %v", name, got, want)
		}
	}
	enum := func(raw json.RawMessage) []string {
		var e struct {
			Enum []string `json:"enum"`
		}
		_ = json.Unmarshal(raw, &e)
		sort.Strings(e.Enum)
		return e.Enum
	}
	if got := enum(schema.Properties["class"]); !slices.Equal(got, []string{"connector", "enricher", "parser", "target-scan"}) {
		t.Errorf("class enum %v", got)
	}
	if got := enum(sub("permissions")["network"]); !slices.Equal(got, []string{"egress-proxy", "none", "targets", "vendor"}) {
		t.Errorf("network enum %v", got)
	}
}

func sortedKeys(m map[string]json.RawMessage) []string {
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

func TestByteSizeAndDuration(t *testing.T) {
	for in, want := range map[string]ByteSize{"1024": 1024, "512Mi": 512 << 20, "1Gi": 1 << 30, "64MB": 64e6, "2K": 2000} {
		if got, err := ParseByteSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "-1", "1Pi", "lots", "9999999999999Ti"} {
		if _, err := ParseByteSize(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	var d Duration
	if err := json.Unmarshal([]byte(`90`), &d); err != nil || time.Duration(d) != 90*time.Second {
		t.Errorf("seconds: %v %v", d, err)
	}
	if err := json.Unmarshal([]byte(`"bogus"`), &d); err == nil {
		t.Error("bad duration accepted")
	}
}

func TestContractNamesTheManifest(t *testing.T) {
	m, err := LoadManifest([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	c := m.Contract()
	if c.Digest != m.Digest() || c.Class != "target-scan" || c.Network != "none" || len(c.Produces) != 2 {
		t.Fatalf("contract %+v", c)
	}
}
