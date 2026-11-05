package egress

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/webscope"
)

// SECURITY: the web scope's request cap holds exactly per host name: N
// requests pass, the next is refused like a request outside the scope, and
// nothing the task does resets the count: new connections, plain HTTP and
// HTTPS, two ports and a followed redirect all count toward the same name.
// Another host name has a count of its own.
func TestWebRequestCapHoldsAcrossConnectionsAndPorts(t *testing.T) {
	s := &webSite{}
	plain := httptest.NewServer(s.handler())
	defer plain.Close()
	secure := httptest.NewTLSServer(s.handler())
	defer secure.Close()
	const limit = 7
	ws := &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: limit}
	f, pa := webForwarder(t, ws)
	if err := f.CreateAuthority(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(f.AuthorityPEM())
	keep := proxiedClient(t, pa, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	fresh := func() *http.Client { // a new connection for every request
		c := proxiedClient(t, pa, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
		c.Transport.(*http.Transport).DisableKeepAlives = true
		return c
	}
	plainBase := "http://app.test:" + strconv.Itoa(portOf(t, plain.URL))
	tlsBase := "https://app.test:" + strconv.Itoa(portOf(t, secure.URL))
	steps := []struct {
		c   *http.Client
		url string
		n   int // requests this step sends upstream
	}{
		{keep, plainBase + "/a", 1},
		{keep, tlsBase + "/b", 1},
		{keep, tlsBase + "/c", 1}, // the same kept-alive TLS connection
		{fresh(), plainBase + "/d", 1},
		{keep, tlsBase + "/hop", 2}, // the redirect and the page it leads to
	}
	sent := 0
	for _, st := range steps {
		if got, body := get(t, st.c, st.url); got != 200 {
			t.Fatalf("%s (request %d of %d): %d %q", st.url, sent+1, limit, got, body)
		}
		sent += st.n
	}
	if sent != limit-1 || f.WebRequests("app.test") != limit-1 {
		t.Fatalf("counted %d, sent %d", f.WebRequests("APP.test."), sent)
	}
	if got, _ := get(t, fresh(), plainBase+"/last"); got != 200 {
		t.Fatalf("request %d of %d refused: %d", limit, limit, got)
	}
	upstream := len(s.served())
	for _, u := range []string{plainBase + "/over", tlsBase + "/over", plainBase + "/a"} {
		for _, c := range []*http.Client{keep, fresh()} {
			if got, body := get(t, c, u); got != 403 || !strings.Contains(body, "request cap") {
				t.Errorf("%s past the cap: %d %q, want the guard's 403", u, got, body)
			}
		}
	}
	if n := len(s.served()); n != upstream {
		t.Errorf("the server saw %d requests past the cap", n-upstream)
	}
	if f.WebRequests("app.test") != limit {
		t.Errorf("count %d, want %d", f.WebRequests("app.test"), limit)
	}
	// Another host name has a count of its own.
	if got, _ := get(t, keep, "http://other.test:"+strconv.Itoa(portOf(t, plain.URL))+"/a"); got != 200 {
		t.Errorf("other host: %d", got)
	}
	refusals := 0
	for _, r := range f.Refusals() {
		if strings.Contains(r.Reason, "request cap") {
			refusals++
		}
	}
	if refusals != 6 {
		t.Errorf("%d request cap refusals recorded, want 6", refusals)
	}
}

// SECURITY: a scope of GET and HEAD (what path discovery runs under) lets
// only those through: POST, OPTIONS, PUT and DELETE are refused before
// anything reaches the server, and a refused request does not spend the cap.
func TestWebScopeGetHeadOnly(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	f, pa := webForwarder(t, &webscope.Scope{Methods: []string{"GET", "HEAD"}, MaxRequestsPerHost: 10})
	c := proxiedClient(t, pa, nil)
	base := "http://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	for _, m := range []string{"POST", "OPTIONS", "PUT", "DELETE", "PATCH"} {
		req, _ := http.NewRequest(m, base+"/public/x", strings.NewReader("x"))
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != 403 || resp.Header.Get("X-Openctem-Egress") != "refused" {
			t.Errorf("%s: %d, want the guard's 403", m, resp.StatusCode)
		}
	}
	if n := len(s.served()); n != 0 {
		t.Errorf("the server saw %d requests: %v", n, s.served())
	}
	if f.WebRequests("app.test") != 0 {
		t.Errorf("refused requests spent the cap: %d", f.WebRequests("app.test"))
	}
	req, _ := http.NewRequest(http.MethodHead, base+"/public/x", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("HEAD: %d", resp.StatusCode)
	}
	if got, _ := get(t, c, base+"/public/y"); got != 200 || f.WebRequests("app.test") != 2 {
		t.Errorf("GET: %d, count %d", got, f.WebRequests("app.test"))
	}
}

// A scope without a cap counts nothing and refuses nothing for volume.
func TestWebScopeWithoutCapCountsNothing(t *testing.T) {
	s := &webSite{}
	srv := httptest.NewServer(s.handler())
	defer srv.Close()
	f, pa := webForwarder(t, testWebScope)
	c := proxiedClient(t, pa, nil)
	base := "http://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	for i := 0; i < 20; i++ {
		if got, _ := get(t, c, base+"/public/"+strconv.Itoa(i)); got != 200 {
			t.Fatalf("request %d: %d", i, got)
		}
	}
	if f.WebRequests("app.test") != 0 {
		t.Errorf("counted without a cap")
	}
}
