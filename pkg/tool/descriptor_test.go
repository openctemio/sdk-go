package tool

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// portScanYAML is a third-party port scanner implementing scan.ports@1.
const portScanYAML = `apiVersion: openctem.io/tool/v1
name: acme-portscan
version: 2.0.0
description: Fast TCP connect port scanner.
publisher: acme
license: MIT
engine: {name: acme-scan, license: Apache-2.0, min_version: 2.3.0, version_probe: [acme-scan, -version]}
presentation: {display_name: Acme port scan, category: network, icon: radar, docs_url: "https://docs.example.com/acme"}
class: target-scan
modes: [daemon, runner]
tier: T1
implements:
  - capability: scan.ports@1
    params:
      ports: {key: ports}
      top_n: {key: top_ports}
      rate: {key: rate, max: 5000}
      protocol: {values: [tcp]}
    output_shape: open_port_assets
consumes: [domain, subdomain, ip_address, host]
produces: [asset:ip_address, asset:host, asset:open_port]
input: {batch: list, max_targets: 5000}
config:
  type: object
  additionalProperties: false
  properties:
    ports: {type: string, pattern: "^[0-9,-]+$", maxLength: 2048}
    top_ports: {type: integer, minimum: 1, maximum: 65535, default: 100}
    rate: {type: integer, minimum: 1, maximum: 5000, default: 1000}
    protocol: {type: string, enum: [tcp], default: tcp}
permissions: {network: targets, proxy: honors}
resources: {cpu: 1, memory: 512Mi, timeout: 6h}
safety: {rate_param: rate, expands_targets: false}
features: {cancel: true}
run:
  profile: exec
  argv: [acme-scan, -list, "{{task.targets_file}}", -json, -rate, "{{config.rate}}"]
  output: {format: jsonl-ctis, from: stdout}
protocol: {min: 1}
sdk: {min: 0.18.0}
`

func TestDescriptorCases(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		errPath string // "" = valid
	}{
		{"valid port scanner", portScanYAML, ""},
		{"no implements is still valid", patch(portScanYAML, "implements", ""), ""},
		{"capability without major", patch(portScanYAML, "  - capability", "  - capability: scan.ports"), "/implements/0/capability"},
		{"capability unknown", patch(portScanYAML, "  - capability", "  - capability: scan.everything@1"), "not in the capability taxonomy"},
		{"capability unknown major", patch(portScanYAML, "  - capability", "  - capability: scan.ports@2"), "not in the capability taxonomy"},
		{"capability look-alike case", patch(portScanYAML, "  - capability", "  - capability: Scan.Ports@1"), "/implements/0/capability"},
		{"capability reserved", "apiVersion: openctem.io/tool/v1\nname: bas\nversion: 1.0.0\nclass: target-scan\ntier: T2\nimplements: [{capability: simulate.attack@1}]\nconsumes: [ip_address]\nproduces: [finding:vulnerability]\n", "reserved"},
		{"duplicate implements", patch(portScanYAML, "implements", "implements: [{capability: scan.ports@1}, {capability: scan.ports@1}]"), "/implements/1/capability"},
		{"tier below floor", patch(portScanYAML, "tier", "tier: T0"), "needs at least T1"},
		{"T2 above floor is allowed", patch(portScanYAML, "tier", "tier: T2"), ""},
		{"unknown output shape", patch(portScanYAML, "    output_shape", "    output_shape: rows"), "/implements/0/output_shape"},
		{"param not standard", patch(portScanYAML, "      rate", "      speed: {key: rate}"), "no standard param \"speed\""},
		{"param key missing", patch(portScanYAML, "      top_n", "      top_n: {key: top}"), "/implements/0/params/top_n/key"},
		{"param key type", patch(portScanYAML, "      ports", "      ports: {key: rate}"), "a port_list param needs"},
		{"param key twice", patch(portScanYAML, "      top_n", "      top_n: {key: rate}"), "already mapped"},
		{"param value outside enum", patch(portScanYAML, "      protocol", "      protocol: {values: [udp]}"), "/implements/0/params/protocol/values/0"},
		{"values on integer", patch(portScanYAML, "      rate", "      rate: {key: rate, values: [a]}"), "only string and list params take values"},
		{"max above capability", patch(portScanYAML, "      rate", "      rate: {key: rate, max: 1000000}"), "/implements/0/params/rate/max"},
		{"min on a string", patch(portScanYAML, "      ports", "      ports: {key: ports, min: 1}"), "min and max are for integer"},
		{"min above max", patch(portScanYAML, "      rate", "      rate: {key: rate, min: 10, max: 5}"), "min above max"},
		{"consumes outside the ports", patch(portScanYAML, "consumes", "consumes: [repository]"), "/consumes/0"},
		{"produces outside the ports", patch(portScanYAML, "produces", "produces: [asset:open_port, finding:vulnerability]"), "/produces/1"},
		{"produces a re-observed input", patch(portScanYAML, "produces", "produces: [asset:open_port, asset:domain]"), ""},
		{"legacy words must repeat implements", portScanYAML + "capabilities: [portscan]\n", "/capabilities/0"},
		{"legacy word equal to the id", portScanYAML + "capabilities: [scan.ports]\n", ""},
		{"batch unknown", patch(portScanYAML, "input", "input: {batch: many}"), "/input/batch"},
		{"max targets on one", patch(portScanYAML, "input", "input: {batch: one, max_targets: 3}"), "/input/max_targets"},
		{"max targets huge", patch(portScanYAML, "input", "input: {batch: list, max_targets: 1000000}"), "/input/max_targets"},
		{"proxy unknown", patch(portScanYAML, "permissions", "permissions: {network: targets, proxy: sometimes}"), "/permissions/proxy"},
		{"proxy without network", "apiVersion: openctem.io/tool/v1\nname: p\nversion: 1.0.0\nclass: parser\ntier: T0\nconsumes: [file:text/plain]\nproduces: [finding:secret]\npermissions: {proxy: honors}\n", "/permissions/proxy"},
		{"egress proxy ignored", patch(portScanYAML, "permissions", "permissions: {network: egress-proxy, proxy: ignores}"), "/permissions/proxy"},
		{"rate param missing", patch(portScanYAML, "safety", "safety: {rate_param: speed}"), "/safety/rate_param"},
		{"rate param not integer", patch(portScanYAML, "safety", "safety: {rate_param: ports}"), "/safety/rate_param"},
		{"side effect unknown", patch(portScanYAML, "safety", "safety: {side_effects: [explodes]}"), "/safety/side_effects/0"},
		{"side effect needs T2", patch(portScanYAML, "safety", "safety: {side_effects: [ioc_in_logs]}"), "declare T2"},
		{"side effect with T2", patch(patch(portScanYAML, "safety", "safety: {side_effects: [ioc_in_logs]}"), "tier", "tier: T2"), ""},
		{"expands on a parser", "apiVersion: openctem.io/tool/v1\nname: p\nversion: 1.0.0\nclass: parser\ntier: T0\nconsumes: [file:text/plain]\nproduces: [finding:secret]\nsafety: {expands_targets: true}\n", "/safety/expands_targets"},
		{"streaming reserved", patch(portScanYAML, "features", "features: {streaming: true}"), "/features/streaming"},
		{"retest twice", patch(portScanYAML, "features", "features: {retest: true}") + "retest: true\n", "/retest"},
		{"retest on exec", patch(portScanYAML, "features", "features: {retest: true}"), "/features/retest"},
		{"display name control", patch(portScanYAML, "presentation", "presentation: {display_name: \"a\\u202eb\"}"), "/presentation/display_name"},
		{"display name long", patch(portScanYAML, "presentation", "presentation: {display_name: \""+strings.Repeat("a", 65)+"\"}"), "/presentation/display_name"},
		{"icon url", patch(portScanYAML, "presentation", "presentation: {icon: \"https://evil.example/x.svg\"}"), "/presentation/icon"},
		{"category unknown", patch(portScanYAML, "presentation", "presentation: {category: weapons}"), "/presentation/category"},
		{"docs url http", patch(portScanYAML, "presentation", "presentation: {docs_url: \"http://docs.example.com\"}"), "/presentation/docs_url"},
		{"docs url javascript", patch(portScanYAML, "presentation", "presentation: {docs_url: \"javascript:alert(1)\"}"), "/presentation/docs_url"},
		{"docs url credentials", patch(portScanYAML, "presentation", "presentation: {docs_url: \"https://u:p@docs.example.com\"}"), "/presentation/docs_url"},
		{"publisher control", patch(portScanYAML, "publisher", "publisher: \"a\\nb\""), "/publisher"},
		{"license not spdx", patch(portScanYAML, "license", "license: \"free for all!\""), "/license"},
		{"engine name", patch(portScanYAML, "engine", "engine: {name: Acme}"), "/engine/name"},
		{"engine license", patch(portScanYAML, "engine", "engine: {name: acme, license: \"???\"}"), "/engine/license"},
		{"engine min version", patch(portScanYAML, "engine", "engine: {name: acme, min_version: latest}"), "/engine/min_version"},
		{"engine probe shell", patch(portScanYAML, "engine", "engine: {name: acme, version_probe: [sh, -c, acme -v]}"), "/engine/version_probe/0"},
		{"engine probe placeholder", patch(portScanYAML, "engine", "engine: {name: acme, version_probe: [acme, \"{{config.rate}}\"]}"), "/engine/version_probe/1"},
		{"engine probe long", patch(portScanYAML, "engine", "engine: {name: acme, version_probe: [a, b, c, d, e, f, g, h, i]}"), "/engine/version_probe"},
		{"sdk too new", patch(portScanYAML, "sdk", "sdk: {min: 9.0.0}"), "/sdk/min"},
		{"sdk not semver", patch(portScanYAML, "sdk", "sdk: {min: next}"), "/sdk/min"},
		{"deprecated", portScanYAML + "deprecated: {since: 2.0.0, replaced_by: acme-portscan2, message: use v2}\n", ""},
		{"deprecated bad since", portScanYAML + "deprecated: {since: soon}\n", "/deprecated/since"},
		{"deprecated bad replacement", portScanYAML + "deprecated: {since: 2.0.0, replaced_by: \"Bad Name\"}\n", "/deprecated/replaced_by"},
		{"deprecated control message", portScanYAML + "deprecated: {since: 2.0.0, message: \"a\\u0007\"}\n", "/deprecated/message"},
		{"unknown descriptor key", patch(portScanYAML, "safety", "safety: {tier_floor: T0}"), "unknown field"},
		{"unknown param mapping key", patch(portScanYAML, "      rate", "      rate: {key: rate, scale: 2}"), "unknown field"},
		{"secrets code finding types", "apiVersion: openctem.io/tool/v1\nname: leaks\nversion: 1.0.0\nclass: target-scan\ntier: T0\nimplements: [{capability: secrets.code@1}]\nconsumes: [repository]\nproduces: [finding:vulnerability]\n", "/produces/0"},
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

func TestDescriptorAccessors(t *testing.T) {
	m, err := LoadManifest([]byte(portScanYAML))
	if err != nil {
		t.Fatal(err)
	}
	caps := m.ImplementedCapabilities()
	if len(caps) != 1 || caps[0].Ref() != "scan.ports@1" {
		t.Fatalf("implemented %v", caps)
	}
	im, ok := m.Implementation("scan.ports@1")
	if !ok || im.Params["top_n"].ConfigKey("top_n") != "top_ports" || im.Params["protocol"].ConfigKey("protocol") != "protocol" {
		t.Fatalf("implementation %+v", im)
	}
	if _, ok := m.Implementation("probe.http@1"); ok {
		t.Fatal("not implemented")
	}
	if !m.Batches() || m.RetestFeature() {
		t.Fatal("batch/retest")
	}
	if m.MinimumTier() != T1 {
		t.Fatalf("minimum tier %s", m.MinimumTier())
	}
	m.Safety.SideEffects = []string{SideEffectStateChange}
	if m.MinimumTier() != T2 {
		t.Fatal("a side effect makes the tool intrusive")
	}
	m.Safety = nil
	m.Tier = T0 // a Go literal can say anything; the floor still holds
	if m.MinimumTier() != T1 {
		t.Fatal("the capability floor raises a lower declared tier")
	}
	c := m.Contract()
	if !slices.Equal(c.Implements, []string{"scan.ports@1"}) || !c.Batch {
		t.Fatalf("contract %+v", c)
	}
}

// Existing manifests keep their digest: every new key is optional and
// omitted when unset.
func TestDigestStableForOlderManifests(t *testing.T) {
	m, err := LoadManifest([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:fe91f1288587f42c3584ad6e31b57bb59bd16f71d2d4046a2699fc1690d11e3d"
	if got := m.Digest(); got != want {
		t.Fatalf("digest of an unchanged manifest moved: %s", got)
	}
	p, err := LoadManifest([]byte(portScanYAML))
	if err != nil {
		t.Fatal(err)
	}
	q := p
	q.Implements = slices.Clone(p.Implements)
	q.Implements[0].OutputShape = "ip_ports"
	if p.Digest() == q.Digest() {
		t.Fatal("an implements change must change the digest")
	}
	// Map order does not matter.
	js, _ := json.Marshal(p)
	again, err := LoadManifest(js)
	if err != nil || again.Digest() != p.Digest() {
		t.Fatalf("round trip: %v %s %s", err, again.Digest(), p.Digest())
	}
}

func TestBuilderImplementsMapsParams(t *testing.T) {
	tl, err := Define("dotenv", "1.0.0").
		Implements("vuln.templates@1").
		Targets("http_service").
		Produces("finding:misconfiguration").
		Params(StringParam("path").Default("/.env"), IntParam("rate").Default(10).Range(1, 100), BoolParam("tags")).
		BatchTargets(100).
		Handle(func(Context, *Job, Emit) error { return nil }).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	m := tl.Manifest()
	im, _ := m.Implementation("vuln.templates@1")
	if _, ok := im.Params["rate"]; !ok {
		t.Fatalf("rate not mapped: %+v", im.Params)
	}
	if _, ok := im.Params["tags"]; ok {
		t.Fatal("a boolean key must not map to a list param")
	}
	if !m.Batches() || m.Input.MaxTargets != 100 {
		t.Fatal("batch")
	}

	// Explicit mapping and the deprecated Capabilities still work.
	tl, err = Define("ports", "1.0.0").Tier(T1).
		ImplementsWith(Implementation{Capability: "scan.ports@1", Params: map[string]ParamMapping{"top_n": {Key: "top"}}}).
		Capabilities("scan.ports").
		Targets("ip_address").Produces("asset:open_port").
		Params(IntParam("top").Default(100).Range(1, 65535)).
		Handle(func(Context, *Job, Emit) error { return nil }).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	if got := tl.Manifest().Implements[0].Params; !reflect.DeepEqual(got, map[string]ParamMapping{"top_n": {Key: "top"}}) {
		t.Fatalf("explicit mapping changed: %v", got)
	}

	// A builder tool below the capability's tier floor does not build.
	_, err = Define("lazy", "1.0.0").Tier(T0).Implements("scan.ports@1").
		Targets("ip_address").Produces("asset:open_port").
		Handle(func(Context, *Job, Emit) error { return nil }).Build()
	if err == nil || !strings.Contains(err.Error(), "needs at least T1") {
		t.Fatalf("err = %v", err)
	}
}

func TestRetestFeatureSpellings(t *testing.T) {
	if !(Manifest{Retest: true}).RetestFeature() || !(Manifest{Features: &Features{Retest: true}}).RetestFeature() || (Manifest{}).RetestFeature() {
		t.Fatal("RetestFeature")
	}
	r := WithRetest(Define("rt", "1.0.0").Targets("domain").Produces("finding:vulnerability").
		Manifest(func(m *Manifest) { m.Features = &Features{Retest: true} }).
		Handle(func(Context, *Job, Emit) error { return nil }).MustBuild(), func(RetestContext, Task) error { return nil })
	if m := r.Manifest(); m.Retest || m.Validate() != nil {
		t.Fatalf("features.retest must not be doubled: %+v %v", m.Features, m.Validate())
	}
}

func TestSemverLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"0.18.0", "0.19.0", true}, {"0.18.0", "0.18.0", false}, {"1.0.0", "0.99.9", false}, {"v0.2.0-rc1", "0.2.1", true}} {
		if got := semverLess(c.a, c.b); got != c.want {
			t.Errorf("semverLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
	if tierOf(5) != T2 || tierOf(-1) != T0 || tierRank("T9") != -1 {
		t.Fatal("tier helpers")
	}
}
