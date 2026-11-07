package conformance

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/contract/webpath"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/webdiff"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// fakeWebPaths is a path discovery tool over pkg/webdiff: it reads the
// candidates (one per line) and the web scope, drops what the scope refuses
// or what names a state-changing action, and reports the confirmed hits.
// $CONFORMANCE_IGNORE_SCOPE=1 ignores the scope; $CONFORMANCE_NAIVE=1
// reports every 2xx answer without the differ.
func fakeWebPaths(origin, scopeFile, listFile string) []ctis.Endpoint {
	var scope *webscope.Scope
	if b, err := os.ReadFile(scopeFile); err == nil {
		_ = json.Unmarshal(b, &scope)
	}
	if os.Getenv("CONFORMANCE_IGNORE_SCOPE") == "1" {
		scope = nil
	}
	base, err := url.Parse(origin)
	if err != nil {
		return nil
	}
	f, err := os.Open(listFile)
	if err != nil {
		return nil
	}
	defer f.Close()
	var cands []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		p := "/" + strings.TrimLeft(strings.TrimSpace(sc.Text()), "/")
		u := base.JoinPath(p)
		if p == "/" || webpath.Destructive(p) || scope.Allows("GET", u, []string{base.Hostname()}) != nil {
			continue
		}
		cands = append(cands, p)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	var out []ctis.Endpoint
	if os.Getenv("CONFORMANCE_NAIVE") == "1" {
		for _, p := range cands {
			resp, err := client.Get(base.JoinPath(p).String()) //nolint:noctx // the fixture
			if err != nil {
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode/100 == 2 {
				out = append(out, ctis.Endpoint{Origin: origin, Method: "GET", Path: p, StatusCode: resp.StatusCode})
			}
		}
		return out
	}
	o := webdiff.Options{Rate: 500}
	if scope != nil {
		o.MaxRequests = scope.MaxRequestsPerHost
	}
	pr, err := webdiff.New(client, origin, o)
	if err != nil {
		return nil
	}
	ctx := context.Background()
	if _, err := pr.Canary(ctx); err != nil {
		return nil
	}
	for _, p := range cands {
		r, err := pr.Check(ctx, p)
		if errors.Is(err, webdiff.ErrStopped) {
			break
		}
		if r.Hit != nil {
			out = append(out, webdiff.Endpoint(origin, r.Hit))
		}
	}
	return out
}

const webPathsTool = `tier: T1
implements: [{capability: enumerate.web_paths@1}]
consumes: [web_origin]
produces: [endpoint]
permissions: {network: targets}
features: {web_scope: true}
content: [{slot: paths, kind: wordlist, purpose: web-paths, max_lines: 1000}]
run: {profile: exec, argv: [EXE, "{{target.value}}", "{{task.web_scope_file}}", "{{content.paths}}"], output: {format: ctis, from: stdout}}
`

// SECURITY (acceptance): a path discovery tool on the calibrated differ that
// keeps to the web scope passes the enumerate.web_paths suite; one that
// ignores the scope fails it (denied directory, destructive entry), and
// one that reports every 200 fails it (soft-404 answers reported).
func TestContractSuite_WebPaths(t *testing.T) {
	m := fakeManifest(t, webPathsTool, nil)
	if r := runContract(m, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "webpaths"}}); len(r.errs) > 0 {
		t.Fatalf("a differ-based tool that keeps to the scope: %v", r.errs)
	}
	r := runContract(m, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "webpaths", "CONFORMANCE_IGNORE_SCOPE": "1"}})
	if !hasErr(r, "which the web scope denies") {
		t.Fatalf("a tool that ignores the scope passed: %v", r.errs)
	}
	r = runContract(m, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "webpaths", "CONFORMANCE_NAIVE": "1"}})
	if !hasErr(r, "want exactly") {
		t.Fatalf("a tool that reports soft-404 answers passed: %v", r.errs)
	}
	noSlot := fakeManifest(t, strings.Replace(webPathsTool, "purpose: web-paths", "purpose: params", 1), nil)
	if r := runContract(noSlot, ContractOptions{Capability: true, Env: map[string]string{fakeToolEnv: "webpaths"}}); !hasErr(r, "wordlist content slot") {
		t.Fatalf("a tool without a web-paths slot passed: %v", r.errs)
	}
}
