package tool_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func dotenvTool(t *testing.T, seen *[]string) tool.Tool {
	t.Helper()
	tl, err := tool.Define("dotenv", "1.0.0").
		Describe("Finds .env files a web server serves").
		Targets("http_service", "domain").
		Produces("finding:misconfiguration", "finding:vulnerability", "asset:domain").
		Params(
			tool.StringParam("path").Label("Path").Help("Path to probe").Default("/.env").Pattern("^/").MaxLength(64),
			tool.IntParam("timeout").Label("Timeout (s)").Default(10).Range(1, 60),
			tool.BoolParam("follow").Default(false).PerScan(),
			tool.StringParam("mode").OneOf("fast", "full").Default("fast"),
			tool.ListParam("extra").MaxItems(4),
		).
		Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
			*seen = append(*seen, job.Param("path").String(), job.Param("mode").StringOr("x"),
				strings.Join(job.Param("extra").Strings(), "+"))
			if job.Param("timeout").IntOr(-1) != 10 || job.Param("follow").BoolOr(true) || job.Param("missing").IsSet() ||
				job.Param("missing").IntOr(7) != 7 {
				return tool.Invalid("unexpected parameter values")
			}
			for _, tg := range job.Targets("http_service") {
				if err := emit.Misconfiguration(tg, tool.Issue{RuleID: "dotenv-exposed", Title: ".env is readable", Severity: "high"}); err != nil {
					return err
				}
				if err := emit.Vulnerability(tg, tool.Issue{RuleID: "cve-check", Title: "Known CVE", Severity: "critical", CVE: "CVE-2024-0001"}); err != nil {
					return err
				}
				ctx.TargetDone(tg)
			}
			for _, tg := range job.Targets("domain") {
				ctx.TargetDone(tg) // a domain target is only counted
			}
			return emit.Asset("domain", "a.example")
		}).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	return tl
}

func TestBuilderToolRunsUnderTheRuntimeRules(t *testing.T) {
	var seen []string
	tl := dotenvTool(t, &seen)
	m := tl.Manifest()
	if m.Class != tool.TargetScan || m.Tier != tool.T1 || m.Permissions.Network != tool.NetTargets {
		t.Fatalf("defaults: class %s tier %s network %s", m.Class, m.Tier, m.Permissions.Network)
	}
	schema, err := m.ConfigSchema()
	if err != nil || schema == nil {
		t.Fatalf("schema: %v", err)
	}
	if p := schema.Property("path"); p == nil || p.Title != "Path" {
		t.Fatalf("path property: %+v", p)
	}
	if p := schema.Property("follow"); p == nil || p.Scope != "scan" {
		t.Fatalf("follow property: %+v", p)
	}

	res := testkit.Run(t, tl, tool.Task{
		Targets: []tool.Target{{Ref: "a1", Type: "http_service", Value: "https://a.example"}, {Ref: "a2", Type: "domain", Value: "a.example"}},
		Config:  json.RawMessage(`{"extra":["a","b"]}`),
	})
	res.RequireStatus(t, tool.StatusOK)
	if strings.Join(seen, ",") != "/.env,fast,a+b" {
		t.Fatalf("handler saw %v", seen)
	}
	if len(res.Report.Findings) != 2 || len(res.Report.Assets) == 0 {
		t.Fatalf("report: %d findings, %d assets", len(res.Report.Findings), len(res.Report.Assets))
	}
	var cve string
	for _, f := range res.Report.Findings {
		if f.Vulnerability != nil {
			cve = f.Vulnerability.CVEID
		}
	}
	if cve != "CVE-2024-0001" {
		t.Fatalf("vulnerability CVE %q", cve)
	}
}

func TestBuilderEnforcesDeclaredParameters(t *testing.T) {
	var seen []string
	tl := dotenvTool(t, &seen)
	for name, cfg := range map[string]string{
		"unknown key":       `{"nope":1}`,
		"out of range":      `{"timeout":61}`,
		"not in enum":       `{"mode":"slow"}`,
		"pattern":           `{"path":"etc/passwd"}`,
		"too many items":    `{"extra":["1","2","3","4","5"]}`,
		"wrong type":        `{"follow":"yes"}`,
		"string too long":   `{"path":"/` + strings.Repeat("a", 80) + `"}`,
		"list of non-items": `{"extra":[1]}`,
	} {
		res := testkit.Run(t, tl, tool.Task{Targets: []tool.Target{{Ref: "a1", Type: "http_service", Value: "https://a.example"}}, Config: json.RawMessage(cfg)})
		if res.Status != tool.StatusFailed || res.Err == nil || res.Err.Class != tool.InvalidInput {
			t.Errorf("%s: status %s err %v, want failed invalid_input", name, res.Status, res.Err)
		}
	}
	if len(seen) != 0 {
		t.Fatalf("the handler ran on an invalid configuration: %v", seen)
	}
}

func TestBuilderOutputStaysWithinProduces(t *testing.T) {
	tl := tool.Define("narrow", "1.0.0").Targets("http_service").Produces("finding:misconfiguration").
		Handle(func(ctx tool.Context, job *tool.Job, emit tool.Emit) error {
			err := emit.Vulnerability(job.Targets()[0], tool.Issue{RuleID: "r", Title: "t", Severity: "low"})
			if !errors.Is(err, tool.ErrUndeclaredOutput) {
				return tool.Failed(errors.New("an undeclared finding type was accepted"))
			}
			ctx.TargetDone(job.Targets()[0])
			return nil
		}).MustBuild()
	res := testkit.Run(t, tl, tool.Task{Targets: []tool.Target{{Ref: "a1", Type: "http_service", Value: "https://a.example"}}})
	res.RequireStatus(t, tool.StatusPartial) // the quarantined record makes the task partial
	if len(res.Report.Findings) != 0 {
		t.Fatalf("quarantined finding delivered: %+v", res.Report.Findings)
	}
}

func TestBuilderRefusesBadDeclarations(t *testing.T) {
	h := func(tool.Context, *tool.Job, tool.Emit) error { return nil }
	cases := map[string]*tool.Builder{
		"no handler":       tool.Define("ok-name", "1.0.0").Produces("finding:misconfiguration"),
		"bad name":         tool.Define("Bad Name", "1.0.0").Produces("finding:misconfiguration").Handle(h),
		"no produces":      tool.Define("ok-name", "1.0.0").Handle(h),
		"secret parameter": tool.Define("ok-name", "1.0.0").Produces("finding:misconfiguration").Params(tool.StringParam("api_key")).Handle(h),
		"duplicate key":    tool.Define("ok-name", "1.0.0").Produces("finding:misconfiguration").Params(tool.IntParam("a"), tool.IntParam("a")).Handle(h),
		"T2 parser":        tool.Define("ok-name", "1.0.0").Class(tool.Parser).Tier(tool.T2).Produces("finding:misconfiguration").Handle(h),
		"params and schema": tool.Define("ok-name", "1.0.0").Produces("finding:misconfiguration").Params(tool.IntParam("a")).
			Manifest(func(m *tool.Manifest) { m.Config = json.RawMessage(`{"type":"object","properties":{}}`) }).Handle(h),
	}
	for name, b := range cases {
		if _, err := b.Build(); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustBuild must panic on an invalid declaration")
		}
	}()
	tool.Define("x", "1.0.0").MustBuild()
}

func TestBuilderParserDefaultsToT0(t *testing.T) {
	tl := tool.Define("lines", "1.0.0").Class(tool.Parser).Targets("file:text/plain").Produces("finding:misconfiguration").
		Handle(func(tool.Context, *tool.Job, tool.Emit) error { return nil }).MustBuild()
	if m := tl.Manifest(); m.Tier != tool.T0 || m.Permissions.Network != tool.NetNone {
		t.Fatalf("parser defaults: tier %s network %s", m.Tier, m.Permissions.Network)
	}
}
