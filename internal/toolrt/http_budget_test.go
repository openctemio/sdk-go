package toolrt

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// SECURITY: the task's own client keeps to the web scope's request cap too:
// N requests to the host are sent, the next fails before it is sent, a
// followed redirect counts, and a method outside a GET/HEAD scope is
// refused without spending the cap.
func TestHTTPRequestCap(t *testing.T) {
	var seen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		if r.URL.Path == "/hop" {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Value: srv.URL}},
		WebScope: &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 4}}
	c := NewHTTPClient(httpTool, task)
	do := func(method, path string) error {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(""))
		resp, err := c.Do(req)
		if err == nil {
			_ = resp.Body.Close()
		}
		return err
	}
	for _, m := range []string{"POST", "OPTIONS", "PUT"} {
		if err := do(m, "/x"); !errors.Is(err, webscope.ErrOutOfScope) {
			t.Errorf("%s: %v", m, err)
		}
	}
	for _, p := range []string{"/a", "/hop"} { // 3 requests
		if err := do("GET", p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	if err := do("HEAD", "/b"); err != nil {
		t.Fatalf("request 4 of 4: %v", err)
	}
	if err := do("GET", "/c"); !errors.Is(err, webscope.ErrOutOfScope) || !strings.Contains(err.Error(), "request cap") {
		t.Fatalf("request past the cap: %v", err)
	}
	if n := seen.Load(); n != 4 {
		t.Errorf("the server saw %d requests, want 4", n)
	}
}
