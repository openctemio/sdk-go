package core

import (
	"context"
	"testing"
)

// A job that asks the tool for its top-N port list must not run outside
// ports.allow: the sdk cannot prove the tool's list is inside the allow-list.
func TestLocalPolicy_TopPortsRefusedWithPortsAllow(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // fullPolicy sets ports.allow
	ctx := context.Background()
	scan := func(id string, cfg map[string]any, key string) *Command {
		return cmdWith(id, "scan", map[string]any{"scanner": "httpx", "target": "203.0.113.9", key: cfg})
	}
	for name, tc := range map[string]struct {
		cmd  *Command
		rule string
	}{
		"top_ports 1000":              {scan("a", map[string]any{"top_ports": 1000}, "config"), "ports.allow"},
		"top_n 1000":                  {scan("b", map[string]any{"top_n": 1000}, "config"), "ports.allow"},
		"top_ports in scanner_config": {scan("c", map[string]any{"top_ports": 100}, "scanner_config"), "ports.allow"},
		"ports keyword full":          {scan("d", map[string]any{"ports": "full"}, "config"), "ports.allow"},
		"ports keyword top":           {scan("e", map[string]any{"ports": "top-1000"}, "config"), "ports.allow"},
		"explicit allowed list":       {scan("f", map[string]any{"ports": "80,443"}, "config"), ""},
		"explicit outside list":       {scan("g", map[string]any{"ports": "22"}, "config"), "ports.allow"},
		"null top_n is no request":    {scan("h", map[string]any{"top_n": nil}, "config"), ""},
		"no port setting":             {scan("i", map[string]any{"rate": 10}, "config"), ""},
	} {
		err := lp.AdmitCommand(ctx, tc.cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
}

// Without ports.allow a top-N job is unchanged.
func TestLocalPolicy_TopPortsAdmittedWithoutPortsAllow(t *testing.T) {
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	err := lp.AdmitCommand(context.Background(), cmdWith("a", "scan", map[string]any{
		"scanner": "httpx", "target": "203.0.113.9", "config": map[string]any{"top_ports": 1000}}))
	if err != nil {
		t.Fatalf("no ports.allow, top_ports must run: %v", err)
	}
}

// A capability job's standard params become the tool's config, so ports.allow
// applies to them as to config (same bypass class as config's "ports").
func TestLocalPolicy_PortsAllowAppliesToCapabilityParams(t *testing.T) {
	lp := mustPolicy(t, fullPolicy) // ports.allow "80,443"
	job := func(capRef string, params map[string]any) *Command {
		return cmdWith("p", "scan", map[string]any{"scanner": "httpx", "capability": capRef,
			"target": "203.0.113.9", "params": params})
	}
	for name, tc := range map[string]struct {
		cmd  *Command
		rule string
	}{
		"top_n":               {job("scan.ports@1", map[string]any{"top_n": 1000}), "ports.allow"},
		"top_ports":           {job("scan.ports@1", map[string]any{"top_ports": 100}), "ports.allow"},
		"ports full range":    {job("scan.ports@1", map[string]any{"ports": "1-65535"}), "ports.allow"},
		"ports outside":       {job("scan.ports@1", map[string]any{"ports": "22,80"}), "ports.allow"},
		"ports array outside": {job("scan.ports@1", map[string]any{"ports": []string{"80", "22"}}), "ports.allow"},
		"ports inside":        {job("scan.ports@1", map[string]any{"ports": "80,443"}), ""},
		"ports array inside":  {job("scan.ports@1", map[string]any{"ports": []string{"80", "443"}}), ""},
		"null top_n":          {job("scan.ports@1", map[string]any{"top_n": nil}), ""},
		"unknown capability":  {job("nope.nothing@1", map[string]any{"ports": "22"}), "ports.allow"},
		"unrelated param":     {job("scan.ports@1", map[string]any{"rate": 10}), ""},
		"no params":           {job("scan.ports@1", nil), ""},
		"hosts ports param":   {job("discover.hosts@1", map[string]any{"ports": "1-1024"}), "ports.allow"},
	} {
		err := lp.AdmitCommand(context.Background(), tc.cmd)
		if tc.rule == "" && err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
		if tc.rule != "" && !isRule(err, tc.rule) {
			t.Errorf("%s: err %v, want rule %s", name, err, tc.rule)
		}
	}
}

// Without ports.allow, params are unchanged.
func TestLocalPolicy_CapabilityParamsAdmittedWithoutPortsAllow(t *testing.T) {
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n")
	err := lp.AdmitCommand(context.Background(), cmdWith("a", "scan", map[string]any{
		"scanner": "httpx", "capability": "scan.ports@1", "target": "203.0.113.9",
		"params": map[string]any{"top_n": 1000, "ports": "1-65535"}}))
	if err != nil {
		t.Fatalf("no ports.allow, params must run: %v", err)
	}
}
