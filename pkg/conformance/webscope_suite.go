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
