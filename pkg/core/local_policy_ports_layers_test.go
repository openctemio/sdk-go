package core

import (
	"context"
	"strings"
	"testing"
)

// ports.allow is the sensor owner's protection against its own platform, so
// it applies to every place a job can name ports, not only to config["ports"]:
// the tenant's and the sensor's settings layers reach the tool's settings
// (resolveScanSettings) like the job's config does.
func TestLocalPolicy_PortsAllowAppliesToSettingsLayers(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // ports.allow "80,443, 8000-8999"
	scan := func(layers map[string]any) *Command {
		return cmdWith("l", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9", "settings_layers": layers})
	}
	for name, tc := range map[string]struct {
		cmd  *Command
		rule string
	}{
		"tenant ports full range":      {scan(map[string]any{"tenant": map[string]any{"ports": "1-65535"}}), "ports.allow"},
		"tenant ports outside":         {scan(map[string]any{"tenant": map[string]any{"ports": "22,80"}}), "ports.allow"},
		"sensor ports full range":      {scan(map[string]any{"sensor": map[string]any{"ports": "1-65535"}}), "ports.allow"},
		"tenant top_ports":             {scan(map[string]any{"tenant": map[string]any{"top_ports": 1000}}), "ports.allow"},
		"sensor top_n":                 {scan(map[string]any{"sensor": map[string]any{"top_n": 100}}), "ports.allow"},
		"tenant ports keyword":         {scan(map[string]any{"tenant": map[string]any{"ports": "full"}}), "ports.allow"},
		"tenant ports as a list":       {scan(map[string]any{"tenant": map[string]any{"ports": []string{"80", "22"}}}), "ports.allow"},
		"tenant ports inside":          {scan(map[string]any{"tenant": map[string]any{"ports": "80,443"}}), ""},
		"sensor ports inside":          {scan(map[string]any{"sensor": map[string]any{"ports": "8000-8100"}}), ""},
		"layers without a port key":    {scan(map[string]any{"tenant": map[string]any{"rate_limit": 100}, "sensor": map[string]any{"threads": 4}}), ""},
		"null top_ports is no request": {scan(map[string]any{"tenant": map[string]any{"top_ports": nil}}), ""},
		"empty layers":                 {scan(map[string]any{}), ""},
	} {
		err := lp.AdmitCommand(context.Background(), tc.cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
	// The refusal says which layer carried the list.
	err := lp.AdmitCommand(context.Background(), scan(map[string]any{"tenant": map[string]any{"ports": "1-65535"}}))
	if err == nil || !strings.Contains(err.Error(), "tenant settings layer") {
		t.Errorf("the refusal does not name the layer: %v", err)
	}
	// Without ports.allow the layers are unchanged.
	open := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	if err := open.AdmitCommand(context.Background(), scan(map[string]any{"tenant": map[string]any{"ports": "1-65535", "top_ports": 1000}})); err != nil {
		t.Errorf("no ports.allow, layers must run: %v", err)
	}
}

// A port list is a port list whatever its key is called: a tool's schema can
// name it port_range, tcp_ports or put it in a group, and a capability param
// can map to any config key. A list that narrows the scan (exclude_ports)
// is not a request for more ports.
func TestLocalPolicy_PortsAllowByKeyShape(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	for name, tc := range map[string]struct {
		cfg  map[string]any
		rule string
	}{
		"port_range":                 {map[string]any{"port_range": "1-65535"}, "ports.allow"},
		"port_ranges list":           {map[string]any{"port_ranges": []any{"80", "1-1024"}}, "ports.allow"},
		"tcp_ports":                  {map[string]any{"tcp_ports": "22"}, "ports.allow"},
		"udp_ports":                  {map[string]any{"udp_ports": "53"}, "ports.allow"},
		"port_list":                  {map[string]any{"port_list": "22,80"}, "ports.allow"},
		"single port":                {map[string]any{"port": 22}, "ports.allow"},
		"top_ports_count":            {map[string]any{"top_ports_count": 100}, "ports.allow"},
		"top-ports hyphen":           {map[string]any{"top-ports": 100}, "ports.allow"},
		"grouped ports":              {map[string]any{"net": map[string]any{"ports": "1-65535"}}, "ports.allow"},
		"grouped top_ports":          {map[string]any{"net": map[string]any{"top_ports": 100}}, "ports.allow"},
		"deeply grouped ports":       {map[string]any{"a": map[string]any{"b": map[string]any{"ports": "22"}}}, "ports.allow"},
		"port_range inside":          {map[string]any{"port_range": "80,443"}, ""},
		"tcp_ports inside":           {map[string]any{"tcp_ports": "8080"}, ""},
		"exclude_ports is narrowing": {map[string]any{"exclude_ports": "22"}, ""},
		"skip_ports is narrowing":    {map[string]any{"skip_ports": "22-25"}, ""},
		"port switch on":             {map[string]any{"scan_ports": true}, "ports.allow"},
		"port switch off":            {map[string]any{"scan_ports": false}, ""},
		"support is not a port key":  {map[string]any{"support": "22", "export_format": "json", "rate": 10}, ""},
		"proxy_port is not a list":   {map[string]any{"proxy_port": 3128}, ""},
	} {
		for _, key := range []string{"config", "scanner_config"} {
			cmd := cmdWith("k", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9", key: tc.cfg})
			err := lp.AdmitCommand(context.Background(), cmd)
			if tc.rule == "" && err != nil {
				t.Errorf("%s in %s: refused: %v", name, key, err)
			}
			if tc.rule != "" && !isRule(err, tc.rule) {
				t.Errorf("%s in %s: err %v, want rule %s", name, key, err, tc.rule)
			}
		}
	}
	// The same key shapes in a settings layer.
	cmd := cmdWith("k", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9",
		"settings_layers": map[string]any{"sensor": map[string]any{"port_range": "1-65535"}}})
	if err := lp.AdmitCommand(context.Background(), cmd); !isRule(err, "ports.allow") {
		t.Errorf("port_range in a layer: %v", err)
	}
}

// A port-scanning capability with no ports named runs the tool's default
// top-N list, which the sdk cannot check against ports.allow: the job is
// refused with the fix. (Until now it was admitted; that was the same
// bypass as top_n, only spelled by leaving the setting out.)
func TestLocalPolicy_PortScanCapabilityMustNamePorts(t *testing.T) {
	lp := mustPolicy(t, fullPolicy)
	job := func(capRef string, rest map[string]any) *Command {
		p := map[string]any{"scanner": "httpx", "capability": capRef, "target": "203.0.113.9"}
		for k, v := range rest {
			p[k] = v
		}
		return cmdWith("c", "scan", p)
	}
	for name, tc := range map[string]struct {
		cmd  *Command
		rule string
	}{
		"no params":                {job("scan.ports@1", nil), "ports.allow"},
		"unrelated param only":     {job("scan.ports@1", map[string]any{"params": map[string]any{"protocol": "tcp"}}), "ports.allow"},
		"null ports param":         {job("scan.ports@1", map[string]any{"params": map[string]any{"ports": nil}}), "ports.allow"},
		"config without ports":     {job("scan.ports@1", map[string]any{"config": map[string]any{"rate": 10}}), "ports.allow"},
		"capability without major": {job("scan.ports", nil), "ports.allow"},
		"ports param inside":       {job("scan.ports@1", map[string]any{"params": map[string]any{"ports": "80,443"}}), ""},
		"ports param and protocol": {job("scan.ports@1", map[string]any{"params": map[string]any{"ports": "443", "protocol": "tcp"}}), ""},
		"ports in config inside":   {job("scan.ports@1", map[string]any{"config": map[string]any{"ports": "443"}}), ""},
		"ports in tenant layer":    {job("scan.ports@1", map[string]any{"settings_layers": map[string]any{"tenant": map[string]any{"ports": "443"}}}), ""},
		"ports param outside":      {job("scan.ports@1", map[string]any{"params": map[string]any{"ports": "22"}}), "ports.allow"},
		// Other capabilities and plain jobs are unchanged.
		"service detection":   {job("detect.service@1", nil), ""},
		"no capability":       {cmdWith("c", "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9"}), ""},
		"capability, no tool": {job("probe.http@1", nil), ""},
	} {
		err := lp.AdmitCommand(context.Background(), tc.cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
	err := lp.AdmitCommand(context.Background(), job("scan.ports@1", nil))
	for _, want := range []string{"name the ports in the job", "default list cannot be checked", "ports.allow"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal must name the fix (%q): %v", want, err)
		}
	}
	// Without ports.allow a port scan with no ports runs.
	open := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	if err := open.AdmitCommand(context.Background(), job("scan.ports@1", nil)); err != nil {
		t.Errorf("no ports.allow, a port scan without ports must run: %v", err)
	}
}
