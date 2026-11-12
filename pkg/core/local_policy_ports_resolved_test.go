package core

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// portsPolicyDoc allows 80 and 443 only.
const portsPolicyDoc = `apiVersion: openctem.io/sensor-policy/v1
targets:
  allow: ["203.0.113.0/24"]
ports:
  allow: "80,443"
`

// portsSchema is a port tool's settings: its port list is called
// port_range, a second list svc_set (only its manifest says that is a port
// list), the top-N count top_ports has a default; exclude_ports narrows.
// Layers set any key; a job's config only the scan-scoped ones.
func portsSchema(defaults string) *SettingsSchema {
	portRange, topPorts := `{"type":"string","maxLength":64,"x-octm-scope":"scan"}`, `{"type":"integer","minimum":1,"maximum":65535,"x-octm-scope":"scan"}`
	switch defaults {
	case "list":
		portRange = `{"type":"string","maxLength":64,"default":"1-1024","x-octm-scope":"scan"}`
	case "top":
		topPorts = `{"type":"integer","minimum":1,"maximum":65535,"default":100,"x-octm-scope":"scan"}`
	}
	return MustParseSettingsSchema(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "x-octm-schema-version": 1,
  "type": "object",
  "additionalProperties": false,
  "properties": {
    "port_range": ` + portRange + `,
    "svc_set": {"type":"string","maxLength":64,"x-octm-scope":"scan"},
    "top_ports": ` + topPorts + `,
    "exclude_ports": {"type":"string","maxLength":64,"x-octm-scope":"scan"},
    "rate": {"type":"integer","minimum":1,"maximum":1000,"x-octm-scope":"scan"}
  }
}`)
}

// portsScanner declares portsSchema; declared are the settings its manifest
// says name ports (PortSettingsProvider), nil: it declares none.
type portsScanner struct {
	recordingScanner
	schema   *SettingsSchema
	declared map[string]PortSettingKind
}

func (s *portsScanner) SettingsSchema() *SettingsSchema { return s.schema }
func (s *portsScanner) TakesCapabilityJobs() bool       { return true }

// declaringScanner is a portsScanner whose manifest declares its port keys.
type declaringScanner struct{ portsScanner }

func (s *declaringScanner) PortSettings() map[string]PortSettingKind { return s.declared }

// Nothing a job's settings layers or a tool's own defaults carry loosens
// ports.allow at the executor either (a second line behind admission): the
// tool's resolved settings are checked, whichever layer set them and
// whichever key they are under.
func TestExecuteScan_ResolvedPortsStayInsideLocalPolicy(t *testing.T) {
	lp := mustPolicy(t, portsPolicyDoc)
	run := func(sc Scanner, payload string) (*recordingScanner, error) {
		var rec *recordingScanner
		switch s := sc.(type) {
		case *portsScanner:
			rec = &s.recordingScanner
		case *declaringScanner:
			rec = &s.recordingScanner
		}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(&ScanTargetPolicy{AllowPrivate: true, LookupIP: policyDNS})
		e.SetLocalPolicy(lp)
		raw := `{"scanner":"rec","target":"203.0.113.9",` + payload + `}`
		if !json.Valid([]byte(raw)) {
			t.Fatalf("bad test JSON: %s", raw)
		}
		_, err := e.Execute(context.Background(), &Command{ID: "c1", Type: "scan", Payload: json.RawMessage(raw)})
		return rec, err
	}
	plain := func(defaults string) Scanner { return &portsScanner{schema: portsSchema(defaults)} }
	declares := func(defaults string) Scanner {
		return &declaringScanner{portsScanner{schema: portsSchema(defaults),
			declared: map[string]PortSettingKind{"svc_set": PortSettingList, "top_ports": PortSettingTopN}}}
	}
	for name, tc := range map[string]struct {
		sc      Scanner
		payload string
		refused bool
	}{
		// Layers (bypass: the tenant's and the sensor's layers).
		"tenant layer, whole range":     {plain(""), `"settings_layers":{"tenant":{"port_range":"1-65535"}}`, true},
		"sensor layer, outside":         {plain(""), `"settings_layers":{"sensor":{"port_range":"22,80"}}`, true},
		"tenant layer, inside":          {plain(""), `"settings_layers":{"tenant":{"port_range":"80,443"}}`, false},
		"explicit top-N from a layer":   {plain(""), `"settings_layers":{"tenant":{"port_range":"80","top_ports":1000}}`, true},
		"exclude list narrows":          {plain(""), `"settings_layers":{"tenant":{"port_range":"80","exclude_ports":"22"}}`, false},
		"config list inside":            {plain(""), `"config":{"port_range":"443"}`, false},
		"config list outside":           {plain(""), `"config":{"port_range":"22"}`, true},
		"scan config overrides a layer": {plain(""), `"config":{"port_range":"443"},"settings_layers":{"tenant":{"port_range":"22"}}`, false},
		"layer inside, config outside":  {plain(""), `"config":{"port_range":"22"},"settings_layers":{"tenant":{"port_range":"80"}}`, true},
		// A key only the tool's manifest says is a port list.
		"declared svc_set outside": {declares(""), `"settings_layers":{"sensor":{"svc_set":"1-65535","port_range":"80"}}`, true},
		"declared svc_set inside":  {declares(""), `"settings_layers":{"sensor":{"svc_set":"443"}}`, false},
		// The tool's defaults.
		"default list outside":           {plain("list"), `"config":{"rate":10}`, true},
		"default list replaced inside":   {plain("list"), `"config":{"port_range":"80"}`, false},
		"default top-N, no list named":   {plain("top"), `"config":{"rate":10}`, true},
		"default top-N, nothing at all":  {plain("top"), `"config":{}`, true},
		"default top-N, list named":      {plain("top"), `"config":{"port_range":"80"}`, false},
		"default top-N, list in a layer": {plain("top"), `"settings_layers":{"sensor":{"port_range":"443"}}`, false},
		"declared top-N default":         {declares("top"), `"config":{"rate":10}`, true},
		"no port setting at all":         {plain(""), `"config":{"rate":10}`, false},
		// A port scan that names no ports (admission refuses it first).
		"port scan, no ports":     {plain(""), `"capability":"scan.ports@1","config":{"rate":10}`, true},
		"port scan, ports param":  {plain(""), `"capability":"scan.ports@1","params":{"ports":"80"}`, false},
		"port scan, list setting": {plain(""), `"capability":"scan.ports@1","config":{"port_range":"80"}`, false},
	} {
		sc := tc.sc
		rec, err := run(sc, tc.payload)
		switch {
		case tc.refused && !isRule(err, "ports.allow"):
			t.Errorf("%s: err %v, want a ports.allow refusal", name, err)
		case tc.refused && rec.calls != 0:
			t.Errorf("%s: refused, but the scanner ran", name)
		case !tc.refused && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case !tc.refused && rec.calls != 1:
			t.Errorf("%s: the scanner did not run", name)
		}
	}
}

// The refusal of a default top-N list says what to do.
func TestCheckResolvedPorts_Messages(t *testing.T) {
	lp := mustPolicy(t, portsPolicyDoc)
	ts, err := portsSchema("top").Resolve()
	if err != nil {
		t.Fatal(err)
	}
	err = lp.CheckResolvedPorts(ts, nil, "", false)
	if !isRule(err, "ports.allow") || !strings.Contains(err.Error(), "name the ports in the job") {
		t.Fatalf("default top-N: %v", err)
	}
	// A list a standard param names takes the default's place.
	if err := lp.CheckResolvedPorts(ts, nil, "", true); err != nil {
		t.Fatalf("params name the ports: %v", err)
	}
	// A switch that defaults to off asks for no ports.
	sw := MustParseSettingsSchema(`{"$schema":"https://json-schema.org/draft/2020-12/schema","x-octm-schema-version":1,
	  "type":"object","additionalProperties":false,"properties":{"scan_ports":{"type":"boolean","default":false}}}`)
	off, err := sw.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := lp.CheckResolvedPorts(off, nil, "", false); err != nil {
		t.Fatalf("a port switch that is off: %v", err)
	}
	// No policy, or one without ports.allow: nothing to check.
	open := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	if err := open.CheckResolvedPorts(ts, nil, "scan.ports@1", false); err != nil {
		t.Fatalf("no ports.allow: %v", err)
	}
	if err := (*LocalPolicy)(nil).CheckResolvedPorts(ts, nil, "scan.ports@1", false); err != nil {
		t.Fatalf("no policy: %v", err)
	}
}

// ports.allow as the destination ports the forwarder admits.
func TestLocalPolicy_AllowedPorts(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // "80,443, 8000-8999"
	got := lp.AllowedPorts()
	if len(got) != 2+1000 || got[0] != 80 || got[1] != 443 || got[2] != 8000 || got[len(got)-1] != 8999 {
		t.Fatalf("ports %d: %v...", len(got), got[:4])
	}
	// Overlapping items count once and stay ascending.
	lp = mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nports:\n  allow: \"443,80,80-82,81\"\n")
	if got := lp.AllowedPorts(); len(got) != 4 || got[0] != 80 || got[3] != 443 {
		t.Fatalf("overlapping: %v", got)
	}
	// Every port allowed, no policy, no ports.allow: no restriction.
	for name, p := range map[string]*LocalPolicy{
		"all ports":   mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nports:\n  allow: \"1-65535\"\n"),
		"no ports":    mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n"),
		"nil policy":  nil,
		"empty value": {},
	} {
		if got := p.AllowedPorts(); got != nil {
			t.Errorf("%s: %d ports, want no restriction", name, len(got))
		}
	}
}
