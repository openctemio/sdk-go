package egress

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// SECURITY (end to end, real nuclei; skipped without NUCLEI_REAL_BIN): a
// web-scoped nuclei run with "-iserver http://<server> -pi" behind the
// forwarder registers with the configured interaction server only, with the
// forwarder's token and never one from nuclei; its payloads name the
// server's zone; it polls and deregisters through the forwarder; and the
// web scope still applies to the target.
func TestRealNucleiOOBThroughForwarder(t *testing.T) {
	bin := os.Getenv(EnvRealNuclei)
	if bin == "" {
		t.Skip("set " + EnvRealNuclei + " to a nuclei binary")
	}
	var mu sync.Mutex
	var api []string
	var auth []string
	var cid string
	oob := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		api = append(api, r.Method+" "+r.URL.Path)
		auth = append(auth, r.Header.Get("Authorization"))
		if r.URL.Path == "/register" {
			var reg map[string]any
			_ = json.Unmarshal(body, &reg)
			cid, _ = reg["correlation-id"].(string)
		}
		mu.Unlock()
		switch r.URL.Path {
		case "/register":
			_, _ = io.WriteString(w, `{"message":"registration successful"}`)
		case "/poll":
			_, _ = io.WriteString(w, `{"data":[],"extra":[],"aes_key":"","tlddata":[]}`)
		default:
			_, _ = io.WriteString(w, `{"message":"deregistration successful"}`)
		}
	}))
	defer oob.Close()
	pool := x509.NewCertPool()
	pool.AddCert(oob.Certificate())

	site := &webSite{}
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		queries = append(queries, r.URL.Query().Get("cb"))
		mu.Unlock()
		site.handler().ServeHTTP(w, r)
	}))
	defer srv.Close()

	f := New(Scope{Names: map[string][]netip.Addr{"app.test": {addr("127.0.0.1")}}, Web: testWebScope, WebTargets: []string{"app.test"},
		OOB: &OOBServer{Host: "example.com", Port: portOf(t, oob.URL), Authorization: "forwarder-token", PrivateOK: true, RootCAs: pool}}, Limits{})
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{addr("127.0.0.1")}, nil }
	pa := serve(t, f)

	dir := t.TempDir()
	tpl := `id: oob-probe
info: {name: oob probe, author: openctem, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/public/ok?cb={{interactsh-url}}"]
    matchers:
      - type: word
        part: interactsh_protocol
        words: ["http"]
`
	if err := os.WriteFile(filepath.Join(dir, "oob.yaml"), []byte(tpl), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	target := "http://app.test:" + strconv.Itoa(portOf(t, srv.URL))
	cmd := exec.CommandContext(ctx, bin, "-u", target, "-t", dir, "-proxy", "http://"+pa, "-pi",
		"-iserver", "http://example.com", "-interactions-cooldown-period", "2", "-interactions-poll-duration", "1",
		"-timeout", "5", "-retries", "0", "-disable-update-check", "-jsonl", "-no-color", "-v")
	cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
	out, err := cmd.CombinedOutput()
	if err != nil && ctx.Err() != nil {
		t.Fatalf("nuclei: %v", err)
	}
	text := string(out)
	if strings.Contains(text, "Could not create interactsh client") {
		t.Fatalf("nuclei could not register:\n%s", tail(text, 3000))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(api) < 2 || api[0] != "POST /register" || api[len(api)-1] != "POST /deregister" {
		t.Fatalf("interaction API calls %v\n%s", api, tail(text, 3000))
	}
	for i, a := range auth {
		if a != "forwarder-token" {
			t.Errorf("call %d (%s) carried Authorization %q", i, api[i], a)
		}
	}
	// The payload the target received names the server's zone.
	var payload string
	for _, q := range queries {
		if q != "" {
			payload = q
		}
	}
	if cid == "" || !strings.HasPrefix(payload, cid) || !strings.HasSuffix(payload, ".example.com") {
		t.Fatalf("payload %q, correlation id %q", payload, cid)
	}
	site.assertNoDenied(t)
	recs, _ := f.Records()
	for _, r := range recs {
		if r.Verdict == Refused {
			t.Errorf("refused: %+v", r)
		}
	}
}
