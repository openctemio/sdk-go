package core

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
)

// A port setting is recognized however its name is written: camelCase and
// PascalCase keys are the same words as snake_case ones, and a few port-list
// words are written as one. A word that only ends in "ports" is not one.
func TestPortKeyKind_NameShapes(t *testing.T) {
	for key, want := range map[string]PortSettingKind{
		"portRange": PortSettingList, "PortRange": PortSettingList, "tcpPorts": PortSettingList,
		"TCPPorts": PortSettingList, "udp-ports": PortSettingList, "portList": PortSettingList,
		"portrange": PortSettingList, "tcpports": PortSettingList, "net.portRange": PortSettingList,
		"topPorts": PortSettingTopN, "TopPorts": PortSettingTopN, "topN": PortSettingTopN,
		"topports": PortSettingTopN, "topPortsCount": PortSettingTopN,
		"excludePorts": PortSettingNone, "skipPorts": PortSettingNone, "supports": PortSettingNone,
		"exportFormat": PortSettingNone, "reports": PortSettingNone, "proxyPort": PortSettingNone,
	} {
		if got := portKeyKind(key); got != want {
			t.Errorf("portKeyKind(%q) = %d, want %d", key, got, want)
		}
	}
	if got := portKeyTokens("FOOBarBaz_qux-2Ports"); !slices.Equal(got, []string{"foo", "bar", "baz", "qux", "2", "ports"}) {
		t.Errorf("portKeyTokens = %q", got)
	}
}

// Admission reads camelCase keys and the objects in a list (services:
// [{port: 22}]) like snake_case keys and groups, within the same depth
// bound.
func TestLocalPolicy_PortsAllowCamelCaseAndArrays(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // ports.allow "80,443, 8000-8999"
	deep := map[string]any{"a": []any{map[string]any{"b": []any{map[string]any{"c": []any{map[string]any{"ports": "22"}}}}}}}
	for name, tc := range map[string]struct {
		cfg  map[string]any
		rule string
	}{
		"portRange outside":           {map[string]any{"portRange": "1-65535"}, "ports.allow"},
		"tcpPorts outside":            {map[string]any{"tcpPorts": "22"}, "ports.allow"},
		"topPorts":                    {map[string]any{"topPorts": 1000}, "ports.allow"},
		"portRange inside":            {map[string]any{"portRange": "80,443"}, ""},
		"excludePorts narrows":        {map[string]any{"excludePorts": "22"}, ""},
		"services port outside":       {map[string]any{"services": []any{map[string]any{"name": "ssh", "port": 22}}}, "ports.allow"},
		"services second outside":     {map[string]any{"services": []any{map[string]any{"port": 443}, map[string]any{"port": 22}}}, "ports.allow"},
		"services topPorts":           {map[string]any{"services": []any{map[string]any{"topPorts": 100}}}, "ports.allow"},
		"nested list of lists":        {map[string]any{"groups": []any{[]any{map[string]any{"ports": "22"}}}}, "ports.allow"},
		"services port inside":        {map[string]any{"services": []any{map[string]any{"port": 443}}}, ""},
		"scalars in a plain list":     {map[string]any{"tags": []any{"22", 22}}, ""},
		"objects nested past the cap": {deep, "ports.allow"},
	} {
		cmd := cmdWith("k", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9", "config": tc.cfg})
		err := lp.AdmitCommand(context.Background(), cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
}

// A port number a job names is plain digits: a sign or a leading zero is
// refused, since a tool may read "0022" as octal 18 while the policy reads
// 22. The same holds for a target's port.
func TestLocalPolicy_PortsAllowRefusesNonCanonicalNumbers(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	for name, tc := range map[string]struct {
		ports string
		rule  string
	}{
		"leading zero":          {"0443", "ports.allow"},
		"leading zero in range": {"80-0443", "ports.allow"},
		"plus sign":             {"+443", "ports.allow"},
		"plain":                 {"443", ""},
		"plain range":           {"8000-8100", ""},
	} {
		cmd := cmdWith("z", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9", "config": map[string]any{"ports": tc.ports}})
		err := lp.AdmitCommand(context.Background(), cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
	ctx := context.Background()
	for _, target := range []string{"203.0.113.9:0443", "http://203.0.113.9:0443/", "203.0.113.9:+443"} {
		if err := lp.CheckTarget(ctx, target); err == nil {
			t.Errorf("%s: admitted", target)
		}
	}
}

// A URL target names its port through its scheme: the common schemes' default
// ports are checked like http's and https's, and a scheme this sensor does
// not know, without a port in the URL, is refused under ports.allow.
func TestLocalPolicy_PortsAllowURLSchemes(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	ctx := context.Background()
	for target, rule := range map[string]string{
		"ftp://203.0.113.9/":             "ports.allow", // 21
		"ssh://203.0.113.9":              "ports.allow", // 22
		"redis://203.0.113.9":            "ports.allow", // 6379
		"mongodb+srv://203.0.113.9":      "ports.allow", // unknown default
		"custom://203.0.113.9/x":         "ports.allow", // unknown default
		"ftp://203.0.113.9:8021/":        "",
		"custom://203.0.113.9:8443/x":    "",
		"wss://203.0.113.9/socket":       "",
		"http://203.0.113.9/":            "",
		"postgres://203.0.113.9:8432/db": "",
	} {
		err := lp.CheckTarget(ctx, target)
		if rule == "" && err != nil {
			t.Errorf("%s: refused: %v", target, err)
		}
		if rule != "" && !isRule(err, rule) {
			t.Errorf("%s: err %v, want rule %s", target, err, rule)
		}
	}
	// Without ports.allow an unknown scheme is fine.
	open := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	if err := open.CheckTarget(ctx, "custom://203.0.113.9/x"); err != nil {
		t.Errorf("no ports.allow: %v", err)
	}
}

// portScanTool is a scanner whose manifest implements scan.ports.
type portScanTool struct{ portsScanner }

func (s *portScanTool) ImplementsPortScan() bool { return true }

// A job for a port scanner is a port scan whatever capability it names, or
// when it names none: it must name its ports under ports.allow, or the tool
// scans its default list.
func TestExecuteScan_PortScannerJobWithoutCapabilityMustNamePorts(t *testing.T) {
	lp := mustPolicy(t, portsPolicyDoc)
	for name, tc := range map[string]struct {
		payload string
		refused bool
	}{
		"no capability, no ports":      {`"config":{"rate":10}`, true},
		"other capability, no ports":   {`"capability":"probe.http@1","config":{"rate":10}`, true},
		"no capability, ports inside":  {`"config":{"port_range":"80"}`, false},
		"no capability, ports outside": {`"config":{"port_range":"22"}`, true},
	} {
		sc := &portScanTool{portsScanner{schema: portsSchema("")}}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(&ScanTargetPolicy{AllowPrivate: true, LookupIP: policyDNS})
		e.SetLocalPolicy(lp)
		raw := `{"scanner":"rec","target":"203.0.113.9",` + tc.payload + `}`
		_, err := e.Execute(context.Background(), &Command{ID: "c1", Type: "scan", Payload: json.RawMessage(raw)})
		switch {
		case tc.refused && !isRule(err, "ports.allow"):
			t.Errorf("%s: err %v, want a ports.allow refusal", name, err)
		case tc.refused && sc.calls != 0:
			t.Errorf("%s: refused, but the scanner ran", name)
		case !tc.refused && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	// The same job on a tool that is not a port scanner runs.
	sc := &portsScanner{schema: portsSchema("")}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(&ScanTargetPolicy{AllowPrivate: true, LookupIP: policyDNS})
	e.SetLocalPolicy(lp)
	if _, err := e.Execute(context.Background(), &Command{ID: "c2", Type: "scan",
		Payload: json.RawMessage(`{"scanner":"rec","target":"203.0.113.9","config":{"rate":10}}`)}); err != nil {
		t.Errorf("not a port scanner: %v", err)
	}
}
