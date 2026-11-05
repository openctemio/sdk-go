package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/contract/capability"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/wordlist"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// webPathsCap is the request cap the enumerate.web_paths suite gives its
// task.
const webPathsCap = 80

// webPathsApp is a site whose missing paths answer a soft-404 page (200,
// with the path, a timestamp and a token in it), with two planted paths and
// one under a denied directory. It records every request (method and path).
func webPathsApp() (*httptest.Server, func() []string) {
	var mu sync.Mutex
	var seen []string
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.URL.EscapedPath())
		n++
		i := n
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><head><title>%s home</title></head><body><a href=\"/news\">news</a></body></html>", fixtureTitle)
		case "/backup.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write([]byte("PK\x03\x04 conformance archive"))
		case "/admin-panel":
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><head><title>Console</title></head><body>%s</body></html>",
				strings.Repeat("<p>Operator console section with settings and users.</p>", 40))
		case "/private/data":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"secret":true}`)
		default:
			sum := sha256.Sum256([]byte(fmt.Sprint(i)))
			w.Header().Set("Content-Type", "text/html")
			_, _ = fmt.Fprintf(w, "<html><head><title>%s</title></head><body><p>Nothing at %s (%s, token %s).</p></body></html>",
				fixtureTitle, html.EscapeString(r.URL.Path), time.Now().Format(time.RFC3339Nano), hex.EncodeToString(sum[:16]))
		}
	}))
	return srv, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), seen...) }
}

// webPaths: a path discovery tool given a candidate list (in its web-paths
// wordlist slot), a web scope of GET and HEAD with a request cap and a
// denied directory, on a site whose missing paths answer 200:
//   - reports exactly the planted paths of its list (no soft-404 answer, no
//     path outside its list, nothing denied);
//   - sends only GET and HEAD, nothing under the denied directory, nothing
//     that names a state-changing action, and at most the cap.
func (r *contractRun) webPaths(name string, c capability.Capability) {
	slot := ""
	for _, s := range r.m.Content {
		if s.Kind == "wordlist" && s.Purpose == wordlist.WebPaths {
			slot = s.Slot
			break
		}
	}
	if slot == "" {
		r.t.Errorf("%s: an %s tool reads its candidates from a wordlist content slot of purpose %s", name, c.ID, wordlist.WebPaths)
		return
	}
	if r.m.Features == nil || !r.m.Features.WebScope {
		r.t.Errorf("%s: an %s tool must declare features.web_scope and keep its requests inside the job's web scope", name, c.ID)
		return
	}
	srv, seen := webPathsApp()
	defer srv.Close()
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		r.t.Errorf("%s: the tool takes no URL target", name)
		return
	}
	list := []byte("backup.zip\nadmin-panel\nmissing-one\nmissing-two.php\nprivate/data\nold/\n")
	sum := sha256.Sum256(list)
	task := tool.Task{
		Targets:  []tool.Target{target},
		WebScope: &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: webPathsCap, DenyPaths: []string{"/private"}},
		Content: []tool.TaskContent{{Slot: slot, Mode: tool.ContentCustom,
			Inline: []tool.InlineList{{Purpose: wordlist.WebPaths, SHA256: hex.EncodeToString(sum[:]), Data: list}}}},
	}
	out := r.runSuite(name, c, task)
	requests := seen()
	for _, s := range requests {
		method, p, _ := strings.Cut(s, " ")
		if method != http.MethodGet && method != http.MethodHead {
			r.t.Errorf("%s: the tool sent %s, outside a GET/HEAD scope", name, s)
		}
		if strings.HasPrefix(strings.ToLower(p), "/private") {
			r.t.Errorf("%s: the tool requested %s, which the web scope denies", name, p)
		}
	}
	if len(requests) > webPathsCap {
		r.t.Errorf("%s: the tool sent %d requests, the cap is %d", name, len(requests), webPathsCap)
	}
	if out == nil || out.Report == nil {
		return
	}
	var got []string
	for _, e := range out.Report.Endpoints {
		got = append(got, e.Path)
		if e.StatusCode == 0 {
			r.t.Errorf("%s: endpoint %s has no status", name, e.Path)
		}
	}
	slices.Sort(got)
	if want := []string{"/admin-panel", "/backup.zip"}; !slices.Equal(got, want) {
		r.t.Errorf("%s: reported %v, want exactly %v (the planted paths of the list)", name, got, want)
	}
}
