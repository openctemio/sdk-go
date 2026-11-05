package importcli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const nmapXML = `<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" args="nmap --script-args creds.global=admin:Secr3t">
<host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/><hostnames><hostname name="www.example.com" type="user"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="http" tunnel="ssl" product="nginx" version="1.24.0"/></port></ports></host></nmaprun>`

const testKey = "oct_test_key_do_not_print"

var fixedNow = func() time.Time { return time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC) }

type result struct {
	code           int
	stdout, stderr string
}

func runWith(t *testing.T, args []string, stdin string, vars map[string]string, send func(context.Context, *client, []upload) (*importResponse, error)) result {
	t.Helper()
	var out, errb bytes.Buffer
	if send == nil {
		send = func(context.Context, *client, []upload) (*importResponse, error) {
			t.Fatal("the command sent something")
			return nil, nil
		}
	}
	code := run(args, env{
		stdin: strings.NewReader(stdin), stdout: &out, stderr: &errb,
		getenv: func(k string) string { return vars[k] },
		now:    fixedNow,
		open:   func(p string) (io.ReadCloser, error) { return os.Open(p) },
		send:   send,
	})
	return result{code, out.String(), errb.String()}
}

func TestDryRun_PrintsTheReportAndSendsNothing(t *testing.T) {
	r := runWith(t, []string{"--format", "nmap", "--dry-run"}, nmapXML, map[string]string{EnvAPIKey: testKey, EnvURL: "https://console.example.com"}, nil)
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(r.stdout), &rep); err != nil {
		t.Fatalf("stdout is not one CTIS report: %v\n%s", err, r.stdout)
	}
	if rep["version"] != "2.0" || !strings.Contains(r.stdout, "192.0.2.5:443/tcp") {
		t.Fatalf("report = %s", r.stdout)
	}
	if strings.Contains(r.stdout+r.stderr, "Secr3t") || strings.Contains(r.stdout+r.stderr, testKey) {
		t.Fatal("a secret reached the output")
	}
	if !strings.Contains(r.stderr, "stdin (nmap, nmap 7.95): 3 assets") {
		t.Fatalf("summary = %q", r.stderr)
	}
}

func TestOut_WritesAPrivateFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "scan.ctis.json")
	r := runWith(t, []string{"--format", "lines", "--as", "url", "--tool", "gau", "--out", p}, "https://www.example.com/a?x=1\n", nil, nil)
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v, want 0600", st.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"name": "gau"`) || strings.Contains(string(b), "x=1") {
		t.Fatalf("report = %s", b)
	}
	// The file uploads later as a CTIS report: format auto detects it.
	r = runWith(t, []string{"--dry-run", p}, "", nil, nil)
	if r.code != ExitOK || !strings.Contains(r.stderr, "(ctis, gau)") {
		t.Fatalf("re-reading the offline file: exit %d %s", r.code, r.stderr)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"unknown format":     {"--format", "nope", "--dry-run"},
		"as without lines":   {"--format", "nmap", "--as", "url", "--dry-run"},
		"bad as":             {"--format", "lines", "--as", "everything", "--dry-run"},
		"out and dry-run":    {"--out", "x", "--dry-run"},
		"bad target hint":    {"--target-hint", "planet:earth", "--dry-run"},
		"bad severity":       {"--min-severity", "severe", "--dry-run"},
		"stdin twice":        {"--dry-run", "-", "-"},
		"too many inputs":    append([]string{"--dry-run"}, strings.Split(strings.Repeat("f ", 11), " ")[:11]...),
		"mapping and format": {"--mapping", "m.json", "--format", "nmap", "--dry-run"},
		"reconftw directory": {"--format", "reconftw", "--dry-run"},
	} {
		t.Run(name, func(t *testing.T) {
			if r := runWith(t, args, nmapXML, nil, nil); r.code != ExitUsage {
				t.Fatalf("exit %d, want %d: %s", r.code, ExitUsage, r.stderr)
			}
		})
	}
	// Not parseable input is an input error; an input with nothing in it
	// fails.
	if r := runWith(t, []string{"--format", "nmap", "--dry-run"}, "<x/>", nil, nil); r.code != ExitUsage {
		t.Fatalf("garbage: exit %d", r.code)
	}
	if r := runWith(t, []string{"--format", "lines", "--dry-run"}, "# only a comment\n", nil, nil); r.code != ExitFail {
		t.Fatalf("empty: exit %d", r.code)
	}
}

func TestClient_RefusesKeyOverPlainHTTPAndMissingSettings(t *testing.T) {
	for name, c := range map[string]struct{ url, key string }{
		"plain http":   {"http://console.example.com", testKey},
		"no url":       {"", testKey},
		"no key":       {"https://console.example.com", ""},
		"userinfo url": {"https://u:p@console.example.com", testKey},
		"key newline":  {"https://console.example.com", "a\nb"},
		"ftp":          {"ftp://console.example.com", testKey},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newClient(c.url, c.key); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	if _, err := newClient("http://127.0.0.1:8080", testKey); err != nil {
		t.Fatalf("loopback: %v", err)
	}
}

// fakeConsole answers the upload with a queued receipt and the result
// route with the given final status.
func fakeConsole(t *testing.T, final string, got *[][]byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+testKey {
			http.Error(w, `{"message":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == importPath+"/":
			if r.URL.Query().Get("format") != "ctis" || !strings.HasPrefix(r.Header.Get("Idempotency-Key"), "openctem-import-") {
				http.Error(w, `{"message":"bad request"}`, http.StatusBadRequest)
				return
			}
			_, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
			mr := multipart.NewReader(r.Body, params["boundary"])
			for {
				p, err := mr.NextPart()
				if err != nil {
					break
				}
				b, _ := io.ReadAll(p)
				*got = append(*got, b)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"receipt_id":"0193a000-0000-7000-8000-000000000001","status":"queued","files":[]}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/result"):
			_, _ = w.Write([]byte(`{"receipt_id":"0193a000-0000-7000-8000-000000000001","status":"` + final + `",
"files":[{"name":"stdin.ctis.json","format":"ctis","candidates":2}],
"receipt":{"id":"0193a000-0000-7000-8000-000000000001","status":"completed","received":0,"counts":{"created":0},
"assets":{"created":3,"updated":0},"errors":[],"dispositions":{"out_of_scope\u001b[31m":1}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestUpload_SendsTheDryRunBytesAndPrintsTheReceipt(t *testing.T) {
	dry := runWith(t, []string{"--format", "nmap", "--dry-run"}, nmapXML, nil, nil)
	var got [][]byte
	srv := fakeConsole(t, "applied", &got)
	defer srv.Close()
	vars := map[string]string{EnvAPIKey: testKey, EnvURL: srv.URL}
	r := runWith(t, []string{"--format", "nmap", "--wait", "5s"}, nmapXML, vars, func(ctx context.Context, c *client, f []upload) (*importResponse, error) {
		c.poll = 10 * time.Millisecond
		return c.upload(ctx, f)
	})
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	// The report id is new on every run; everything else is the same bytes.
	if len(got) != 1 || !bytes.Equal(withoutID(got[0]), withoutID([]byte(dry.stdout))) {
		t.Fatalf("the upload is not the dry run's report:\nsent %q\ndry  %q", got, dry.stdout)
	}
	for _, want := range []string{"receipt 0193a000-0000-7000-8000-000000000001: applied", "assets    created 3", "held      2 hosts"} {
		if !strings.Contains(r.stderr, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, r.stderr)
		}
	}
	if strings.Contains(r.stderr, "\x1b") || strings.Contains(r.stderr, testKey) {
		t.Fatalf("stderr holds a terminal escape or the key: %q", r.stderr)
	}
}

func TestUpload_ExitCodes(t *testing.T) {
	for final, want := range map[string]int{"failed": ExitFail, "queued": ExitPending} {
		t.Run(final, func(t *testing.T) {
			var got [][]byte
			srv := fakeConsole(t, final, &got)
			defer srv.Close()
			r := runWith(t, []string{"--format", "nmap", "--wait", "50ms"}, nmapXML, map[string]string{EnvAPIKey: testKey, EnvURL: srv.URL},
				func(ctx context.Context, c *client, f []upload) (*importResponse, error) {
					c.poll = 10 * time.Millisecond
					return c.upload(ctx, f)
				})
			if r.code != want {
				t.Fatalf("exit %d, want %d: %s", r.code, want, r.stderr)
			}
		})
	}
	// A wrong key is refused by the console: exit 1.
	var got [][]byte
	srv := fakeConsole(t, "applied", &got)
	defer srv.Close()
	r := runWith(t, []string{"--format", "nmap"}, nmapXML, map[string]string{EnvAPIKey: "wrong", EnvURL: srv.URL},
		func(ctx context.Context, c *client, f []upload) (*importResponse, error) { return c.upload(ctx, f) })
	if r.code != ExitFail || !strings.Contains(r.stderr, "HTTP 401") {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
}

func TestUpload_NeverFollowsARedirect(t *testing.T) {
	hit := false
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit = true }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	r := runWith(t, []string{"--format", "nmap"}, nmapXML, map[string]string{EnvAPIKey: testKey, EnvURL: srv.URL},
		func(ctx context.Context, c *client, f []upload) (*importResponse, error) { return c.upload(ctx, f) })
	if r.code != ExitFail || hit {
		t.Fatalf("exit %d, redirect followed %v: %s", r.code, hit, r.stderr)
	}
}

func TestMapping_LocalFile(t *testing.T) {
	dir := t.TempDir()
	m := filepath.Join(dir, "waf.json")
	if err := os.WriteFile(m, []byte(`{"apiVersion":"openctem.io/mapping/v2","source":"json","records":[
{"when":{"path":"/detected","equals":true},"kind":"asset","set":{"type":{"const":"web_origin"},"value":"/url"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	in := `[{"url":"https://www.example.com","detected":true,"firewall":"Generic"},{"url":"https://b.example.com","detected":false}]`
	r := runWith(t, []string{"--mapping", m, "--tool", "wafw00f", "--dry-run"}, in, nil, nil)
	if r.code != ExitOK {
		t.Fatalf("exit %d: %s", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "https://www.example.com") || strings.Contains(r.stdout, "b.example.com") || !strings.Contains(r.stdout, `"import_scope": "unknown"`) {
		t.Fatalf("report = %s", r.stdout)
	}
}

func withoutID(b []byte) []byte {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return b
	}
	if md, ok := m["metadata"].(map[string]any); ok {
		delete(md, "id")
	}
	out, _ := json.Marshal(m)
	return out
}
