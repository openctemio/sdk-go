package testkit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// walker requests every path of its config through Context.HTTP and
// reports, as one finding each, the paths that answered.
func walker(features *tool.Features) tool.Tool {
	type cfg struct {
		Paths []string `json:"paths"`
	}
	return tool.New(tool.Manifest{
		Name: "walker", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1, Features: features,
		Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
		Config: []byte(`{"type":"object","additionalProperties":false,"properties":{"paths":{"type":"array","items":{"type":"string"}}}}`),
	}, func(ctx tool.Context, task tool.Task, c cfg) error {
		for _, t := range task.Targets {
			for _, p := range c.Paths {
				resp, err := ctx.HTTP().Get(t.URL(p))
				if err != nil {
					continue
				}
				_ = resp.Body.Close()
				if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "reached",
					Title: "reached " + p, Severity: "info"}); err != nil {
					return err
				}
			}
			ctx.TargetDone(t)
		}
		return nil
	})
}

// recorder is a server that records every path it was asked for; /go
// redirects to /admin/panel.
func recorder(t *testing.T) (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/go" {
			http.Redirect(w, r, "/admin/panel", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// SECURITY: Context.HTTP never sends a request outside the job's web
// scope, redirects and path tricks included.
func TestWebScopeEnforcedOnContextHTTP(t *testing.T) {
	srv, seen := recorder(t)
	task := tool.Task{
		Targets:  []tool.Target{{Ref: "a1", Type: "http_service", Value: srv.URL}},
		Config:   []byte(`{"paths":["/public","/admin/panel","/ADMIN/x","/public/../admin/y","/go"]}`),
		WebScope: &webscope.Scope{DenyPaths: []string{"/admin"}},
	}
	res := Run(t, walker(&tool.Features{WebScope: true}), task)
	res.RequireStatus(t, tool.StatusOK)
	for _, p := range seen() {
		if strings.HasPrefix(strings.ToLower(p), "/admin") {
			t.Fatalf("the server received a denied path: %v", seen())
		}
	}
	if len(res.Report.Findings) != 1 || res.Report.Findings[0].Title != "reached /public" {
		t.Fatalf("findings %+v (server saw %v)", res.Report.Findings, seen())
	}
}

// SECURITY: a networked tool that does not declare features.web_scope is
// refused a job with a web scope: it would run unrestricted.
func TestWebScopeRefusesUndeclaredTool(t *testing.T) {
	srv, seen := recorder(t)
	task := tool.Task{
		Targets:  []tool.Target{{Ref: "a1", Type: "http_service", Value: srv.URL}},
		Config:   []byte(`{"paths":["/public"]}`),
		WebScope: &webscope.Scope{DenyPaths: []string{"/admin"}},
	}
	res := Run(t, walker(nil), task)
	res.RequireStatus(t, tool.StatusFailed)
	if res.Err == nil || res.Err.Class != tool.RefusedByPolicy || !strings.Contains(res.Err.Detail, "features.web_scope") {
		t.Fatalf("err %+v", res.Err)
	}
	if len(seen()) != 0 {
		t.Fatalf("the tool ran: %v", seen())
	}
	// An invalid scope is refused too, never run unrestricted.
	task.WebScope = &webscope.Scope{DenyPaths: []string{"admin"}}
	res = Run(t, walker(&tool.Features{WebScope: true}), task)
	res.RequireStatus(t, tool.StatusFailed)
	if len(seen()) != 0 {
		t.Fatalf("the tool ran with an invalid scope: %v", seen())
	}
}
