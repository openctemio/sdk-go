package tool

import (
	"encoding/json"
	"strings"
	"testing"
)

func loadPortScan(t *testing.T) Manifest {
	t.Helper()
	m, err := LoadManifest([]byte(portScanYAML))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestApplyParams(t *testing.T) {
	m := loadPortScan(t)
	task := Task{Capability: "scan.ports@1", Params: map[string]json.RawMessage{
		"ports": json.RawMessage(`" 80, 443,8000-8100"`), "top_n": json.RawMessage(`1000`),
		"rate": json.RawMessage(`4000`), "protocol": json.RawMessage(`"tcp"`),
	}, Config: json.RawMessage(`{"rate":4000}`)}
	got, err := m.ApplyParams(task)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(got.Config, &cfg)
	if cfg["ports"] != "80,443,8000-8100" || cfg["top_ports"] != float64(1000) || cfg["rate"] != float64(4000) || cfg["protocol"] != "tcp" {
		t.Fatalf("config %v", cfg)
	}
	if got.Params != nil || got.Capability != "scan.ports@1" {
		t.Fatal("params must be consumed, the capability kept")
	}
	// No params: unchanged.
	if got, err := m.ApplyParams(Task{Capability: "scan.ports@1"}); err != nil || got.Config != nil {
		t.Fatalf("%v %s", err, got.Config)
	}
	if got, err := m.ApplyParams(Task{}); err != nil || got.Config != nil {
		t.Fatal("no capability, no params")
	}
}

func TestApplyParamsRefusals(t *testing.T) {
	m := loadPortScan(t)
	p := func(k, v string) map[string]json.RawMessage { return map[string]json.RawMessage{k: json.RawMessage(v)} }
	cases := map[string]struct {
		task Task
		want string
	}{
		"no capability":     {Task{Params: p("rate", `1`)}, "need the task's capability"},
		"not implemented":   {Task{Capability: "probe.http@1"}, "does not implement"},
		"look-alike ref":    {Task{Capability: "scan.ports"}, "does not implement"},
		"unknown param":     {Task{Capability: "scan.ports@1", Params: p("speed", `1`)}, "no standard param"},
		"rate too high":     {Task{Capability: "scan.ports@1", Params: p("rate", `6000`)}, "maximum 5000 of this tool"},
		"top_n zero":        {Task{Capability: "scan.ports@1", Params: p("top_n", `0`)}, "below the minimum 1 of the capability"},
		"rate not integer":  {Task{Capability: "scan.ports@1", Params: p("rate", `1.5`)}, "must be an integer"},
		"rate a string":     {Task{Capability: "scan.ports@1", Params: p("rate", `"10"`)}, "must be an integer"},
		"protocol udp":      {Task{Capability: "scan.ports@1", Params: p("protocol", `"udp"`)}, "not one of"},
		"protocol a list":   {Task{Capability: "scan.ports@1", Params: p("protocol", `["tcp"]`)}, "must be a string"},
		"ports injection":   {Task{Capability: "scan.ports@1", Params: p("ports", `"80;rm -rf /"`)}, "ports and ranges"},
		"ports range order": {Task{Capability: "scan.ports@1", Params: p("ports", `"90-80"`)}, "within 1-65535"},
		"ports too big":     {Task{Capability: "scan.ports@1", Params: p("ports", `"70000"`)}, "within 1-65535"},
		"ports bad list":    {Task{Capability: "scan.ports@1", Params: p("ports", `[true]`)}, "numbers or ranges"},
		"not JSON":          {Task{Capability: "scan.ports@1", Params: p("rate", `{`)}, "not JSON"},
		"config not object": {Task{Capability: "scan.ports@1", Params: p("rate", `1`), Config: json.RawMessage(`[1]`)}, "JSON object"},
		"config conflict":   {Task{Capability: "scan.ports@1", Params: p("rate", `10`), Config: json.RawMessage(`{"rate":20}`)}, "another value"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := m.ApplyParams(tc.task)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if AsError(err).Class != InvalidInput {
				t.Fatalf("class %s", AsError(err).Class)
			}
		})
	}
}

func TestApplyParamsTypes(t *testing.T) {
	// A list param, a boolean and a port list given as a list, into an
	// array config key.
	m := Manifest{Name: "probe", Version: "1.0.0", Class: TargetScan, Tier: T1,
		Implements: []Implementation{{Capability: "probe.http@1", Params: map[string]ParamMapping{
			"ports": {}, "tech_detect": {Key: "td"}}}},
		Consumes: []string{"domain"}, Produces: []string{"asset:http_service"},
		Config: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"ports":{"type":"array","items":{"type":"string"}},"td":{"type":"boolean"}}}`)}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	got, err := m.ApplyParams(Task{Capability: "probe.http@1", Params: map[string]json.RawMessage{
		"ports": json.RawMessage(`[80, "8443", "9000-9001"]`), "tech_detect": json.RawMessage(`true`)}})
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Config) != `{"ports":["80","8443","9000-9001"],"td":true}` {
		t.Fatalf("config %s", got.Config)
	}
	if _, err := m.ApplyParams(Task{Capability: "probe.http@1", Params: map[string]json.RawMessage{"tech_detect": json.RawMessage(`"yes"`)}}); err == nil {
		t.Fatal("a string for a boolean")
	}

	n := Manifest{Name: "nuc", Version: "1.0.0", Class: TargetScan, Tier: T1,
		Implements: []Implementation{{Capability: "vuln.templates@1", Params: map[string]ParamMapping{"tags": {}, "severity": {}}}},
		Consumes:   []string{"domain"}, Produces: []string{"finding:vulnerability"},
		Config: json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{"tags":{"type":"array","items":{"type":"string"}},"severity":{"type":"array","items":{"type":"string"}}}}`)}
	for _, bad := range []string{`"x"`, `[""]`, `[1]`, `["` + strings.Repeat("a", 300) + `"]`} {
		if _, err := n.ApplyParams(Task{Capability: "vuln.templates@1", Params: map[string]json.RawMessage{"tags": json.RawMessage(bad)}}); err == nil {
			t.Errorf("tags %s accepted", bad)
		}
	}
	long := make([]string, 257)
	for i := range long {
		long[i] = `"a"`
	}
	if _, err := n.ApplyParams(Task{Capability: "vuln.templates@1", Params: map[string]json.RawMessage{"tags": json.RawMessage("[" + strings.Join(long, ",") + "]")}}); err == nil {
		t.Error("an unbounded list accepted")
	}
	if _, err := n.ApplyParams(Task{Capability: "vuln.templates@1", Params: map[string]json.RawMessage{"severity": json.RawMessage(`["high","bogus"]`)}}); err == nil {
		t.Error("an enum item outside the capability accepted")
	}
}

func TestTierExceeds(t *testing.T) {
	if T1.Exceeds(T1) || !T2.Exceeds(T1) || T0.Exceeds(T2) || !Tier("T9").Exceeds(T2) {
		t.Fatal("Exceeds")
	}
}
