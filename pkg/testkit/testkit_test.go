package testkit

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// dotenv is the minimal tool of the design: a .env file readable over HTTP
// is a misconfiguration.
var dotenv = tool.New(tool.Manifest{
	Name: "dotenv-check", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	for _, t := range task.Targets {
		resp, err := ctx.HTTP().Get(t.URL("/.env"))
		if err != nil {
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "dotenv-exposed",
				Title: ".env file is publicly readable", Severity: "high"}); err != nil {
				return err
			}
		}
		ctx.TargetDone(t)
	}
	return nil
})

func envServer(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = io.WriteString(w, "KEY=1")
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDotenvGoldenIsStable(t *testing.T) {
	srv := envServer(t)
	task := tool.Task{Targets: []tool.Target{{Ref: "a1", Type: "http_service", Value: srv.URL}}}
	first := Run(t, dotenv, task)
	first.RequireStatus(t, tool.StatusOK)
	if len(first.Report.Findings) != 1 || first.Report.Findings[0].AssetRef != "target-a1" {
		t.Fatalf("report %+v", first.Report)
	}
	a, err := Normalize(first.Report)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		b, _ := Normalize(Run(t, dotenv, task).Report)
		if string(a) != string(b) {
			t.Fatalf("normalized reports differ:\n%s\n%s", a, b)
		}
	}
	// The golden file keeps the server's address out: the target is
	// rewritten to a fixed value.
	first.Report.Assets[0].Value, first.Report.Assets[0].Name = "http://127.0.0.1:PORT", "http://127.0.0.1:PORT"
	first.Golden(t, "testdata/dotenv.golden.json")
	if !strings.Contains(string(a), `"<provenance>"`) || strings.Contains(string(a), `"timestamp"`) {
		t.Fatalf("normalization: %s", a)
	}
}

func TestUnreachableTargetIsPartial(t *testing.T) {
	srv := envServer(t)
	task := tool.Task{Targets: []tool.Target{
		{Ref: "a1", Type: "http_service", Value: srv.URL},
		{Ref: "dead", Type: "http_service", Value: "http://127.0.0.1:1"},
	}}
	res := Run(t, dotenv, task)
	res.RequireStatus(t, tool.StatusPartial)
	if len(res.Targets) != 2 || res.Targets[1].State != tool.StateFailed || res.Targets[1].Class != tool.TargetUnreachable {
		t.Fatalf("targets %+v", res.Targets)
	}
}

// A tool's HTTP client reaches only the task's targets.
func TestHTTPOutsideTheTargetsIsRefused(t *testing.T) {
	other := envServer(t)
	srv := envServer(t)
	probe := tool.New(tool.Manifest{
		Name: "pivot", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
	}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
		// other runs on 127.0.0.1 too, so reach it by name.
		_, err := ctx.HTTP().Get(strings.Replace(other.URL, "127.0.0.1", "localhost", 1) + "/.env")
		return err
	})
	res := Run(t, probe, tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: srv.URL}}})
	if res.Status != tool.StatusFailed || !strings.Contains(res.Err.Error(), "not allowed") {
		t.Fatalf("status %s err %v", res.Status, res.Err)
	}
}

// An undeclared credential is never delivered, a declared one is, and its
// value never reaches the logs.
func TestCredentialsAndRedaction(t *testing.T) {
	var gotUndeclared error
	tl := tool.New(tool.Manifest{
		Name: "feed", Version: "1.0.0", Class: tool.Connector, Tier: tool.T0,
		Produces:    []string{"asset:domain"},
		Permissions: tool.Permissions{Network: tool.NetVendor, VendorHosts: []string{"api.example.com"}, Credentials: []tool.CredentialReq{{Name: "api_key", Kind: "api_key"}}},
	}, func(ctx tool.Context, _ tool.Task, _ tool.NoConfig) error {
		_, gotUndeclared = ctx.Secret("db_password")
		k, err := ctx.Secret("api_key")
		if err != nil {
			return err
		}
		ctx.Log().Info("calling the API with key " + k.Reveal())
		ctx.Log().Info("as an attribute", "key", k.Reveal(), "typed", k)
		return ctx.Emit().Asset(ctis.Asset{Type: "domain", Value: "a.example"})
	})
	res := Run(t, tl, tool.Task{}, Options{Secrets: map[string]string{"api_key": "sk-live-123456", "db_password": "hunter2"}})
	res.RequireStatus(t, tool.StatusOK)
	if !errors.Is(gotUndeclared, tool.ErrUndeclaredCredential) {
		t.Fatalf("undeclared credential: %v", gotUndeclared)
	}
	all := fmt.Sprintf("%+v", res.Logs)
	if strings.Contains(all, "sk-live-123456") || !strings.Contains(all, tool.Redacted) {
		t.Fatalf("logs: %s", all)
	}
}

// Undeclared output is quarantined and the task ends partial; invalid
// configuration never reaches the tool; a panic is a crash.
func TestRuntimeRulesInTests(t *testing.T) {
	sneaky := tool.New(tool.Manifest{
		Name: "sneaky", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"},
	}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
		err := ctx.Emit().Asset(ctis.Asset{Type: "ip_address", Value: "10.0.0.1"})
		if !errors.Is(err, tool.ErrUndeclaredOutput) {
			return fmt.Errorf("undeclared asset accepted: %v", err)
		}
		for _, tg := range task.Targets {
			ctx.TargetDone(tg)
		}
		return nil
	})
	res := Run(t, sneaky, tool.Task{Targets: []tool.Target{{Ref: "d", Type: "domain", Value: "a.example"}}})
	res.RequireStatus(t, tool.StatusPartial)
	if res.Stats.Quarantined["asset:ip_address"] != 1 || len(res.Report.Assets) != 0 {
		t.Fatalf("stats %+v assets %+v", res.Stats, res.Report.Assets)
	}

	type cfg struct {
		Depth int `json:"depth" min:"1" max:"3" default:"1"`
	}
	ran := false
	strict := tool.New(tool.Manifest{
		Name: "strict", Version: "1.0.0", Class: tool.Parser, Tier: tool.T0,
		Consumes: []string{"file:text/plain"}, Produces: []string{"finding:secret"},
	}, func(tool.Context, tool.Task, cfg) error { ran = true; return nil })
	res = Run(t, strict, tool.Task{Config: []byte(`{"depth":9}`)})
	if res.Status != tool.StatusFailed || res.Err.Class != tool.InvalidInput || ran {
		t.Fatalf("invalid config: %s %v ran=%t", res.Status, res.Err, ran)
	}

	boom := tool.New(tool.Manifest{
		Name: "boom", Version: "1.0.0", Class: tool.Parser, Tier: tool.T0,
		Consumes: []string{"file:text/plain"}, Produces: []string{"finding:secret"},
	}, func(tool.Context, tool.Task, tool.NoConfig) error { panic("bad tool") })
	res = Run(t, boom, tool.Task{})
	if res.Status != tool.StatusFailed || res.Err.Class != tool.ToolCrashed {
		t.Fatalf("panic: %s %v", res.Status, res.Err)
	}
}

func TestArtifactsAreCapped(t *testing.T) {
	tl := tool.New(tool.Manifest{
		Name: "art", Version: "1.0.0", Class: tool.Parser, Tier: tool.T0,
		Consumes: []string{"file:text/plain"}, Produces: []string{"finding:secret"},
	}, func(ctx tool.Context, _ tool.Task, _ tool.NoConfig) error {
		if _, err := ctx.Artifact("../escape.txt", "text/plain"); err == nil {
			return errors.New("path escape accepted")
		}
		w, err := ctx.Artifact("raw.txt", "text/plain")
		if err != nil {
			return err
		}
		_, _ = io.WriteString(w, "raw output")
		return w.Close()
	})
	res := Run(t, tl, tool.Task{})
	res.RequireStatus(t, tool.StatusOK)
	if string(res.Artifacts["raw.txt"]) != "raw output" {
		t.Fatalf("artifacts %v", res.Artifacts)
	}
}

func TestMain(m *testing.M) {
	// The golden file lives next to the test.
	_ = os.MkdirAll(filepath.Join("testdata"), 0o750)
	os.Exit(m.Run())
}
