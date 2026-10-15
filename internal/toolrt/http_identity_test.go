package toolrt

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: the task's identification (the organization's User-Agent and
// headers, such as a bug-bounty program's required header) is on EVERY
// request the tool sends through Context.HTTP: first requests, later
// requests and redirects, and it wins over a value the tool sets itself, so
// a tool cannot probe a program's targets without it or under another name.
func TestIdentityOnEveryRequest(t *testing.T) {
	type seen struct{ ua, bounty, scan string }
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, seen{r.UserAgent(), r.Header.Get("X-Bug-Bounty"), r.Header.Get("X-Scan-Id")})
		mu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	m := httpTool
	m.HTTP = &tool.HTTPSpec{UserAgent: "acme-scanner/2.0", Headers: map[string]string{"X-Scan-Id": "run-7"}}
	task := tool.Task{
		Targets:  []tool.Target{{Ref: "a", Value: srv.URL}},
		HTTP:     &tool.HTTPSpec{UserAgent: "jdoe-research", Headers: map[string]string{"X-Scan-Id": "run-7", "X-Bug-Bounty": "jdoe"}},
		Identity: &tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}},
	}
	c := NewHTTPClient(m, task)

	// A plain request, one that sets its own User-Agent and program header,
	// one that tries to send the header twice, and a redirect.
	plain, _ := http.NewRequest(http.MethodGet, srv.URL+"/a", nil)
	own, _ := http.NewRequest(http.MethodGet, srv.URL+"/b", nil)
	own.Header.Set("User-Agent", "sneaky/1")
	own.Header.Set("X-Bug-Bounty", "someone-else")
	twice, _ := http.NewRequest(http.MethodGet, srv.URL+"/c", nil)
	twice.Header.Add("X-Bug-Bounty", "jdoe")
	twice.Header.Add("X-Bug-Bounty", "extra")
	redirect, _ := http.NewRequest(http.MethodGet, srv.URL+"/start", nil)
	for _, req := range []*http.Request{plain, own, twice, redirect} {
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if len(got) != 5 {
		t.Fatalf("requests seen: %d, want 5 (the redirect is followed)", len(got))
	}
	for i, s := range got {
		if s.ua != "jdoe-research" || s.bounty != "jdoe" {
			t.Fatalf("request %d sent User-Agent %q, X-Bug-Bounty %q; want the identification", i, s.ua, s.bounty)
		}
	}
	// The tool's own non-identification headers keep their usual rule (a
	// request's own value wins); only the identification is forced.
	if got[0].scan != "run-7" {
		t.Fatalf("the manifest header is still a default: %+v", got[0])
	}
	if twice.Header.Values("X-Bug-Bounty")[1] != "extra" {
		t.Fatal("the caller's request must not be modified")
	}
}

// Without an identification nothing is forced: a request's own values win.
func TestNoIdentityNothingForced(t *testing.T) {
	srv := uaServer(t)
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Value: srv.URL}}}
	if got, err := get(t, NewHTTPClient(httpTool, task), srv.URL, "mine/1"); err != nil || got != "mine/1" {
		t.Fatalf("%q %v", got, err)
	}
}
