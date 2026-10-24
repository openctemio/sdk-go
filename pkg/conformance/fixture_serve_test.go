package conformance

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

func writeFixture(t *testing.T, body string) (string, tool.Fixture) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "task.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, tool.Fixture{Name: "f", Task: "task.json", Expect: "expect.json"}
}

func TestFixtureServePlaceholders(t *testing.T) {
	const serve = `"serve":{"status":200,"headers":{"Server":"fixture"},"body":"<title>ok</title>","paths":{"/.env":{"status":403,"body":"SECRET=x"}}},`
	for _, tc := range []struct {
		name, value, want string
	}{
		{"url", "{{fixture.url}}", "http://127.0.0.1:PORT"},
		{"url path", "{{fixture.url}}/login", "http://127.0.0.1:PORT/login"},
		{"host", "{{fixture.host}}", "127.0.0.1"},
		{"port", "{{fixture.port}}", "PORT"},
		{"host_port", "{{fixture.host_port}}", "127.0.0.1:PORT"},
		{"spaces", "{{ fixture.host }}", "127.0.0.1"},
		{"none", "example.com", "example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, f := writeFixture(t, `{`+serve+`"id":"x","targets":[{"ref":"t1","type":"http_service","value":"`+tc.value+`"}]}`)
			fx, err := loadFixtureTask(dir, f)
			if err != nil {
				t.Fatal(err)
			}
			defer fx.Close()
			_, port, _ := strings.Cut(fx.norm.hostPort, ":")
			if got, want := fx.Task.Targets[0].Value, strings.ReplaceAll(tc.want, "PORT", port); got != want {
				t.Fatalf("got %q want %q", got, want)
			}
		})
	}
}

func TestFixtureServeRefusals(t *testing.T) {
	target := `"targets":[{"ref":"t1","type":"http_service","value":"{{fixture.url}}"}]`
	for _, tc := range []struct{ name, body, want string }{
		{"crlf value", `{"serve":{"headers":{"X":"a\r\nSet-Cookie: b=c"}},` + target + `}`, "CR or LF"},
		{"crlf name", `{"serve":{"headers":{"X\nY":"a"}},` + target + `}`, "CR, LF"},
		{"crlf path header", `{"serve":{"paths":{"/a":{"headers":{"X":"a\nb"}}}},` + target + `}`, "CR or LF"},
		{"bad status", `{"serve":{"status":99},` + target + `}`, "status 99"},
		{"path without slash", `{"serve":{"paths":{"a":{}}},` + target + `}`, "does not start with /"},
		{"unknown placeholder", `{"serve":{},"targets":[{"ref":"t1","type":"http_service","value":"{{fixture.nope}}"}]}`, "unknown placeholder"},
		{"placeholder without serve", `{` + target + `}`, "needs a serve member"},
		{"unknown serve key", `{"serve":{"bodie":"x"},` + target + `}`, "unknown field"},
		{"big body", `{"serve":{"body":"` + strings.Repeat("a", maxServeBody+1) + `"},` + target + `}`, "over"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, f := writeFixture(t, tc.body)
			fx, err := loadFixtureTask(dir, f)
			if err == nil {
				fx.Close()
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q lacks %q", err, tc.want)
			}
		})
	}
	t.Run("bounds", func(t *testing.T) {
		h := map[string]string{}
		for i := 0; i <= maxServeHeaders; i++ {
			h[strings.Repeat("a", i+1)] = "v"
		}
		if err := validateServe(&serveSpec{Headers: h}); err == nil {
			t.Fatal("33 headers accepted")
		}
		p := map[string]servePathSpec{}
		for i := 0; i <= maxServePaths; i++ {
			p["/"+strings.Repeat("a", i)] = servePathSpec{}
		}
		if err := validateServe(&serveSpec{Paths: p}); err == nil {
			t.Fatal("65 paths accepted")
		}
	})
}

func TestFixtureServeAnswersAndStripsServe(t *testing.T) {
	dir, f := writeFixture(t, `{"serve":{"status":200,"headers":{"Server":"fixture"},"body":"hello","paths":{"/.env":{"status":403,"body":"SECRET=x","headers":{"X-A":"b"}}}},
"id":"x","targets":[{"ref":"t1","type":"http_service","value":"{{fixture.url}}"}]}`)
	fx, err := loadFixtureTask(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path string) (int, string, http.Header) {
		resp, err := http.Get(fx.Task.Targets[0].Value + path) //nolint:noctx // a loopback test
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b), resp.Header
	}
	if c, b, h := get("/anything"); c != 200 || b != "hello" || h.Get("Server") != "fixture" {
		t.Fatalf("default: %d %q %v", c, b, h)
	}
	if c, b, h := get("/.env"); c != 403 || b != "SECRET=x" || h.Get("X-A") != "b" || h.Get("Server") != "fixture" {
		t.Fatalf("override: %d %q %v", c, b, h)
	}
	fx.Close()
	if _, err := http.Get(fx.Task.Targets[0].Value); err == nil { //nolint:noctx,bodyclose // the server must be down
		t.Fatal("the server is still up after Close")
	}
}

func TestFixtureServeTLS(t *testing.T) {
	dir, f := writeFixture(t, `{"serve":{"tls":true,"body":"s"},"targets":[{"ref":"t1","type":"http_service","value":"{{fixture.url}}"}]}`)
	fx, err := loadFixtureTask(dir, f)
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	if !strings.HasPrefix(fx.Task.Targets[0].Value, "https://127.0.0.1:") {
		t.Fatalf("value %q", fx.Task.Targets[0].Value)
	}
	if _, err := http.Get(fx.Task.Targets[0].Value); err == nil { //nolint:noctx,bodyclose // a self-signed cert must be refused by a verifying client
		t.Fatal("a verifying client accepted the self-signed certificate")
	}
}

func TestFixtureNormalize(t *testing.T) {
	n := &fixtureNorm{url: "http://127.0.0.1:4321", hostPort: "127.0.0.1:4321"}
	for _, tc := range []struct{ name, in, want string }{
		{"url", `{"a":"http://127.0.0.1:4321/x"}`, `{"a":"{{fixture.url}}/x"}`},
		{"host_port", `{"a":"127.0.0.1:4321"}`, `{"a":"{{fixture.host_port}}"}`},
		{"nested and twice", `{"a":[{"b":"see http://127.0.0.1:4321 and 127.0.0.1:4321"}]}`, `{"a":[{"b":"see {{fixture.url}} and {{fixture.host_port}}"}]}`},
		{"other port kept", `{"a":"http://127.0.0.1:43210/x"}`, `{"a":"http://127.0.0.1:43210/x"}`},
		{"other host kept", `{"a":"http://127.0.0.2:4321"}`, `{"a":"http://127.0.0.2:4321"}`},
		{"escaped chars kept", `{"a":"<a href=\"http://127.0.0.1:4321\">"}`, `{"a":"<a href=\"{{fixture.url}}\">"}`},
		{"numbers kept", `{"p":4321}`, `{"p":4321}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := n.apply([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			compact := strings.Join(strings.Fields(string(got)), "")
			want := strings.Join(strings.Fields(tc.want), "")
			if compact != want {
				t.Fatalf("got %s want %s", compact, want)
			}
		})
	}
}

func TestReplaceBounded(t *testing.T) {
	if got := replaceBounded("a:1 a:12 a:1", "a:1", "X"); got != "X a:12 X" {
		t.Fatal(got)
	}
}
