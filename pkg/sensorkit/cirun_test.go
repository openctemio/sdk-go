package sensorkit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/sdk-go/pkg/core"
)

const testRunToken = "octci_RUNTOKENSECRET0123456789abcdefghijklmnopq"

// fakeCI is a CI provider token endpoint plus the platform's CI routes.
type fakeCI struct {
	t         *testing.T
	srv       *httptest.Server
	mu        sync.Mutex
	audiences []string
	exchanges []map[string]string
	pushes    int
	evalBody  map[string]int
	refuse    bool
	expiresIn time.Duration
	verdict   string
}

func newFakeCI(t *testing.T) *fakeCI {
	f := &fakeCI{t: t, expiresIn: 15 * time.Minute, verdict: "pass"}
	mux := http.NewServeMux()
	mux.HandleFunc("/gh-token", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer gh-request-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		f.mu.Lock()
		f.audiences = append(f.audiences, r.URL.Query().Get("audience"))
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh-oidc-" + r.URL.Query().Get("audience")})
	})
	mux.HandleFunc("/api/v1/ci/oidc/exchange", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.exchanges = append(f.exchanges, body)
		refuse, exp := f.refuse, f.expiresIn
		f.mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "UNAUTHORIZED", "message": "The CI token was not accepted"})
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "token": testRunToken,
			"expires_at": time.Now().Add(exp), "repository": "github.com/acme/api", "is_default_branch": true})
	})
	auth := func(w http.ResponseWriter, r *http.Request) bool {
		if r.Header.Get("Authorization") != "Bearer "+testRunToken {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}
	mux.HandleFunc("/api/v1/ci/runs/run-1/results", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.mu.Lock()
		f.pushes++
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]int{"findings_created": 1})
	})
	mux.HandleFunc("/api/v1/ci/runs/run-1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		if !auth(w, r) {
			return
		}
		f.mu.Lock()
		_ = json.NewDecoder(r.Body).Decode(&f.evalBody)
		v := f.verdict
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"run_id": "run-1", "verdict": v,
			"reasons": []map[string]any{{"code": "severity", "title": "SQL injection", "message": "high", "file": "db.go", "line": 4}},
			"summary": map[string]int{"evaluated": 1, "new": 1, "blocking": 1}, "links": map[string]string{"run": "https://x/ci-runners/run-1"}})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCI) githubEnv(extra map[string]string) func(string) string {
	env := map[string]string{
		"GITHUB_ACTIONS": "true", "ACTIONS_ID_TOKEN_REQUEST_URL": f.srv.URL + "/gh-token?api-version=2.0",
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "gh-request-token",
	}
	for k, v := range extra {
		env[k] = v
	}
	return func(k string) string { return env[k] }
}

func TestDetectCIOIDC(t *testing.T) {
	f := newFakeCI(t)
	cases := map[string]struct {
		cfg  CIRunConfig
		want string
	}{
		"github":    {CIRunConfig{TenantID: "t1", Getenv: f.githubEnv(nil)}, CIProviderGitHub},
		"no tenant": {CIRunConfig{Getenv: f.githubEnv(nil)}, ""},
		"github without id-token": {CIRunConfig{TenantID: "t1", Getenv: func(k string) string {
			return map[string]string{"GITHUB_ACTIONS": "true"}[k]
		}}, ""},
		"gitlab": {CIRunConfig{TenantID: "t1", Getenv: func(k string) string {
			return map[string]string{"GITLAB_CI": "true", "OPENCTEM_ID_TOKEN": "gl"}[k]
		}}, CIProviderGitLab},
		"gitlab without id_tokens": {CIRunConfig{TenantID: "t1", Getenv: func(k string) string {
			return map[string]string{"GITLAB_CI": "true"}[k]
		}}, ""},
	}
	for name, tc := range cases {
		got, ok := DetectCIOIDC(tc.cfg)
		if got != tc.want || ok != (tc.want != "") {
			t.Fatalf("%s: %q %v", name, got, ok)
		}
	}
	if _, err := NewCIRun(CIRunConfig{Getenv: func(string) string { return "" }}); !errors.Is(err, ErrNoCIOIDC) {
		t.Fatalf("no OIDC: %v", err)
	}
}

func TestCIRunGitHub(t *testing.T) {
	f := newFakeCI(t)
	run, err := NewCIRun(CIRunConfig{APIURL: f.srv.URL, TenantID: "t1", Getenv: f.githubEnv(nil)})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := run.PushFindings(ctx, &ctis.Report{Version: "1.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := run.PushFindings(ctx, &ctis.Report{Version: "1.0"}); err != nil {
		t.Fatal(err)
	}
	if len(f.exchanges) != 1 || f.pushes != 2 {
		t.Fatalf("exchanges %d pushes %d", len(f.exchanges), f.pushes)
	}
	if f.audiences[0] != "openctem:tenant:t1" || f.exchanges[0]["id_token"] != "gh-oidc-openctem:tenant:t1" || f.exchanges[0]["tenant_id"] != "t1" {
		t.Fatalf("exchange = %v audiences %v", f.exchanges, f.audiences)
	}
	v, err := run.Evaluate(ctx, 2)
	if err != nil || v.Failed() || f.evalBody["scan_failures"] != 2 {
		t.Fatalf("evaluate: %+v %v %v", v, err, f.evalBody)
	}
	if strings.Contains(run.String(), testRunToken) || run.Info().Repository != "github.com/acme/api" {
		t.Fatalf("String/Info: %s %+v", run, run.Info())
	}
	var buf bytes.Buffer
	f.verdict = "fail"
	v, _ = run.Evaluate(ctx, 0)
	WriteVerdict(&buf, v)
	if !v.Failed() || !strings.Contains(buf.String(), "FAIL") || !strings.Contains(buf.String(), "db.go:4") || strings.Contains(buf.String(), testRunToken) {
		t.Fatalf("verdict output: %s", buf.String())
	}
}

// A token about to expire is renewed for the same run (GitHub can mint a
// new OIDC token); the request names the run.
func TestCIRunRenewsForTheSameRun(t *testing.T) {
	f := newFakeCI(t)
	f.expiresIn = time.Minute
	run, _ := NewCIRun(CIRunConfig{APIURL: f.srv.URL, TenantID: "t1", Audience: "custom-aud", Getenv: f.githubEnv(nil)})
	ctx := context.Background()
	if err := run.Open(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := run.PushFindings(ctx, &ctis.Report{Version: "1.0"}); err != nil {
		t.Fatal(err)
	}
	if len(f.exchanges) != 2 || f.exchanges[1]["run_id"] != "run-1" || f.audiences[1] != "custom-aud" {
		t.Fatalf("renewal: %v %v", f.exchanges, f.audiences)
	}
}

func TestCIRunGitLabExchangesOnce(t *testing.T) {
	f := newFakeCI(t)
	f.expiresIn = time.Minute
	env := map[string]string{"GITLAB_CI": "true", "MY_TOKEN": "gl-oidc"}
	run, err := NewCIRun(CIRunConfig{APIURL: f.srv.URL, TenantID: "t1", IDTokenVar: "MY_TOKEN", Getenv: func(k string) string { return env[k] }})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range 2 {
		if _, err := run.PushFindings(ctx, &ctis.Report{Version: "1.0"}); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.exchanges) != 1 || f.exchanges[0]["id_token"] != "gl-oidc" {
		t.Fatalf("gitlab exchanges: %v", f.exchanges)
	}
}

func TestCIRunRefusalNeverLeaksTokens(t *testing.T) {
	f := newFakeCI(t)
	f.refuse = true
	run, _ := NewCIRun(CIRunConfig{APIURL: f.srv.URL, TenantID: "t1", Getenv: f.githubEnv(nil)})
	_, err := run.PushFindings(context.Background(), &ctis.Report{Version: "1.0"})
	if !errors.Is(err, ErrCIExchangeRefused) {
		t.Fatalf("err = %v", err)
	}
	for _, secret := range []string{"gh-oidc-", "gh-request-token", testRunToken} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error carries a token: %v", err)
		}
	}
}

type fakeScanner struct {
	name string
	out  []byte
	err  error
}

func (s fakeScanner) Name() string           { return s.name }
func (s fakeScanner) Version() string        { return "1" }
func (s fakeScanner) Capabilities() []string { return []string{"sast"} }
func (s fakeScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "1", nil
}
func (s fakeScanner) Scan(context.Context, string, *core.ScanOptions) (*core.ScanResult, error) {
	return &core.ScanResult{RawOutput: s.out}, s.err
}

type fakeParser struct{}

func (fakeParser) Name() string               { return "fake" }
func (fakeParser) SupportedFormats() []string { return []string{"fake"} }
func (fakeParser) CanParse(b []byte) bool     { return bytes.HasPrefix(b, []byte("FAKE")) }
func (fakeParser) Parse(context.Context, []byte, *core.ParseOptions) (*ctis.Report, error) {
	return &ctis.Report{Version: "1.0", Findings: []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "x", Severity: ctis.SeverityHigh}}}, nil
}

func TestKitRunOnce(t *testing.T) {
	f := newFakeCI(t)
	f.verdict = "fail"
	k := &Kit{handlers: map[string]core.CommandExecutor{}}
	k.AddParser(fakeParser{})
	k.AddScanner(fakeScanner{name: "good", out: []byte("FAKE data")})
	k.AddScanner(fakeScanner{name: "empty"})
	k.AddScanner(fakeScanner{name: "broken", err: errors.New("boom")})
	run, _ := NewCIRun(CIRunConfig{APIURL: f.srv.URL, TenantID: "t1", Getenv: f.githubEnv(nil)})
	var out bytes.Buffer
	res, err := k.RunOnce(context.Background(), run, RunOnceOptions{Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if res.Reports != 1 || res.ScanFailures != 1 || !res.Verdict.Failed() || f.evalBody["scan_failures"] != 1 {
		t.Fatalf("result = %+v eval %v\n%s", res, f.evalBody, out.String())
	}
	if _, err := k.RunOnce(context.Background(), nil, RunOnceOptions{}); err == nil {
		t.Fatal("RunOnce without a run")
	}
}
