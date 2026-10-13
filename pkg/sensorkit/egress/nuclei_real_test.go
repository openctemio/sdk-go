package egress

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// EnvRealNuclei names a real nuclei binary for the end-to-end refusal test
// (skipped without it).
const EnvRealNuclei = "NUCLEI_REAL_BIN"

// writeRefusalTemplates writes one template for an allowed path and many
// for denied paths (GET, POST with a body, two raw requests on one
// connection), more than nuclei's per-host error budget used below.
func writeRefusalTemplates(t *testing.T, denied int) string {
	t.Helper()
	dir := t.TempDir()
	write := func(id, body string) {
		if err := os.WriteFile(filepath.Join(dir, id+".yaml"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("allowed", `id: allowed
info: {name: allowed, author: openctem, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/public/ok"]
    matchers:
      - type: word
        words: ["page /public/ok"]
`)
	for i := range denied {
		switch i % 3 {
		case 0:
			write(fmt.Sprintf("denied-get-%d", i), fmt.Sprintf(`id: denied-get-%d
info: {name: denied, author: openctem, severity: info}
http:
  - method: GET
    path: ["{{BaseURL}}/admin/get-%d"]
    matchers:
      - type: word
        words: ["page /admin"]
`, i, i))
		case 1:
			write(fmt.Sprintf("denied-post-%d", i), fmt.Sprintf(`id: denied-post-%d
info: {name: denied, author: openctem, severity: info}
http:
  - method: POST
    path: ["{{BaseURL}}/admin/post-%d"]
    body: "user=admin&pass=admin"
    headers:
      Content-Type: application/x-www-form-urlencoded
    matchers:
      - type: word
        words: ["page /admin"]
`, i, i))
		default:
			write(fmt.Sprintf("denied-raw-%d", i), fmt.Sprintf(`id: denied-raw-%d
info: {name: denied, author: openctem, severity: info}
http:
  - raw:
      - |
        POST /admin/raw-%d HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"a":1}
      - |
        GET /admin/raw-%d-b HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: word
        words: ["page /admin"]
`, i, i, i))
		}
	}
	return dir
}

// SECURITY (acceptance): the real nuclei binary through the forwarder, with
// a web scope that denies /admin and more denied templates than nuclei's
// per-host error budget: the refusals are answered, never read as host
// errors, so nuclei does not skip the host as unresponsive, the allowed
// template still finds its path, and the server never sees /admin.
func TestRealNucleiRefusalsDoNotTripTheHostBreaker(t *testing.T) {
	bin := os.Getenv(EnvRealNuclei)
	if bin == "" {
		t.Skipf("%s is not set", EnvRealNuclei)
	}
	for _, useTLS := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[useTLS], func(t *testing.T) {
			s := &webSite{}
			var srv *httptest.Server
			scheme := "http"
			if useTLS {
				srv, scheme = httptest.NewTLSServer(s.handler()), "https"
			} else {
				srv = httptest.NewServer(s.handler())
			}
			defer srv.Close()
			f, pa := webForwarder(t, testWebScope)
			if err := f.CreateAuthority(); err != nil {
				t.Fatal(err)
			}
			templates := writeRefusalTemplates(t, 30)
			target := scheme + "://app.test:" + strconv.Itoa(portOf(t, srv.URL))
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, "-u", target, "-t", templates, "-proxy", "http://"+pa,
				"-mhe", "3", "-c", "5", "-timeout", "5", "-retries", "0", "-disable-update-check",
				"-no-interactsh", "-jsonl", "-no-color", "-v")
			cmd.Env = append(os.Environ(), "HOME="+t.TempDir())
			out, err := cmd.CombinedOutput()
			if err != nil && ctx.Err() != nil {
				t.Fatalf("nuclei: %v", err)
			}
			text := string(out)
			// A refusal is an answer, not a broken connection: nuclei
			// counts EOF, resets and timeouts toward its per-host error
			// budget (-mhe) and then skips the whole host.
			for _, sign := range []string{"Could not execute request", "EOF", "connection reset"} {
				if strings.Contains(text, sign) {
					t.Errorf("nuclei saw a connection error (%q), which counts toward its host error budget:\n%s", sign, tail(text, 3000))
					break
				}
			}
			if strings.Contains(text, "unresponsive") {
				t.Errorf("nuclei skipped the host as unresponsive:\n%s", tail(text, 3000))
			}
			if !strings.Contains(text, `"template-id":"allowed"`) {
				t.Errorf("the allowed template found nothing:\n%s", tail(text, 3000))
			}
			s.assertNoDenied(t)
		})
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
