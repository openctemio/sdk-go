package conformance

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// The paths the web-scope suite denies.
var deniedPaths = []string{"/admin", "/logout"}

// webScopeApp is a site whose pages link to allowed and denied paths, by
// plain links, a redirect, a form and a script. It records every path it
// is asked for.
func webScopeApp() (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	page := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><head><title>%s</title></head><body>%s</body></html>", fixtureTitle, body)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			page(w, `<a href="/public/a">a</a> <a href="/admin/secret">admin</a> <a href="/logout">logout</a>
<a href="/public/../admin/dots">dots</a> <a href="/ADMIN/upper">upper</a> <a href="/go">go</a>
<form action="/admin/form" method="get"><input name="q"></form>
<script>fetch("/admin/api")</script>`)
		case "/go":
			http.Redirect(w, r, "/admin/redirected", http.StatusFound)
		case "/public/a":
			page(w, `<a href="/public/b">b</a> <a href="/admin/deep">deep</a>`)
		default:
			page(w, "page")
		}
	}))
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// webScope: a crawler or DAST tool given a web scope that denies /admin and
// /logout never requests either, whatever the site links to, and still
// reaches the allowed pages. A tool that does not declare features.web_scope
// is refused the job, which fails the suite.
func (r *contractRun) webScope(name string, c capability.Capability) {
	srv, seen := webScopeApp()
	defer srv.Close()
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		r.t.Errorf("%s: the tool takes no URL target", name)
		return
	}
	task := tool.Task{Targets: []tool.Target{target}, WebScope: &webscope.Scope{DenyPaths: deniedPaths}}
	if r.m.Features == nil || !r.m.Features.WebScope {
		r.t.Errorf("%s: a %s tool must declare features.web_scope and keep its requests inside the job's web scope", name, c.ID)
		return
	}
	out := r.runSuite(name, c, task)
	paths := seen()
	for _, p := range paths {
		for _, d := range deniedPaths {
			if strings.HasPrefix(strings.ToLower(p), d) {
				r.t.Errorf("%s: the tool requested %s, which the web scope denies (%s)", name, p, d)
			}
		}
	}
	if out != nil && len(paths) == 0 {
		r.t.Errorf("%s: the tool requested nothing from the fixture %s", name, srv.URL)
	}
}

// vulnTemplatesWebScope: a template scanner that declares
// features.web_scope, given a web scope that denies /.env, never requests
// it (in any form, nor behind a redirect) and still finds the exposed
// /.git/config. The platform gives a vuln.templates job a web scope when
// the tenant excludes a path on the host.
func (r *contractRun) vulnTemplatesWebScope(name string, c capability.Capability) {
	var mu sync.Mutex
	var seen []string
	app := fixtureApp()
	app.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen = append(seen, req.URL.Path)
		mu.Unlock()
		if strings.EqualFold(req.URL.Path, "/env") {
			http.Redirect(w, req, "/.env", http.StatusFound)
			return
		}
		app.Config.Handler.ServeHTTP(w, req)
	}))
	defer srv.Close()
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		r.t.Errorf("%s: the tool takes no URL target", name)
		return
	}
	out := r.runSuite(name, c, tool.Task{Targets: []tool.Target{target}, WebScope: &webscope.Scope{DenyPaths: []string{"/.env"}}})
	mu.Lock()
	paths := append([]string(nil), seen...)
	mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(strings.ToLower(p), "/.env") {
			r.t.Errorf("%s: the tool requested %s, which the web scope denies (/.env)", name, p)
		}
	}
	if out != nil && len(out.Report.Findings) == 0 {
		r.t.Errorf("%s: found nothing with a web scope that still allows /.git/config", name)
	}
}

// retests reports whether the tool declares retest (either spelling).
func retests(m tool.Manifest) bool { return m.Retest || (m.Features != nil && m.Features.Retest) }

// retestWebScope: a tool that retests and declares features.web_scope,
// given a retest task with a web scope that denies /.env (the platform
// sends one when the tenant excludes a path on the host), runs it and never
// requests a denied path, in any form nor behind a redirect.
func (r *contractRun) retestWebScope(name string) {
	var mu sync.Mutex
	var seen []string
	app := fixtureApp()
	app.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu.Lock()
		seen = append(seen, req.URL.Path)
		mu.Unlock()
		if strings.EqualFold(req.URL.Path, "/env") {
			http.Redirect(w, req, "/.env", http.StatusFound)
			return
		}
		app.Config.Handler.ServeHTTP(w, req)
	}))
	defer srv.Close()
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		r.t.Errorf("%s: the tool takes no URL target", name)
		return
	}
	target.Ref = "t0"
	task := tool.Task{Targets: []tool.Target{target}, WebScope: &webscope.Scope{DenyPaths: []string{"/.env"}},
		Retest: []tool.RetestItem{{Ref: "f1", Target: "t0", Kind: "finding", RuleID: "conformance-exposed-env"}}}
	out, err := r.run(task)
	if err != nil {
		r.t.Errorf("%s: %v", name, err)
		return
	}
	if out.Err != nil && out.Err.Class == tool.RefusedByPolicy {
		r.t.Errorf("%s: a web-scoped retest was refused: %s", name, out.Err.Detail)
	}
	mu.Lock()
	paths := append([]string(nil), seen...)
	mu.Unlock()
	for _, p := range paths {
		if strings.HasPrefix(strings.ToLower(p), "/.env") {
			r.t.Errorf("%s: the retest requested %s, which the web scope denies (/.env)", name, p)
		}
	}
}
