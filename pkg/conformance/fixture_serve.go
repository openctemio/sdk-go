package conformance

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Bounds of a fixture's "serve" member.
const (
	maxServeBody    = 1 << 20
	maxServeHeaders = 32
	maxServePaths   = 64
)

// serveSpec is the "serve" member of a fixture task file: what the kit's
// loopback server answers while the fixture runs. Only the conformance kit
// and the CLI read it. It is stripped before the task is built, so a sensor
// never sees it, and it is not part of tool.yaml.
type serveSpec struct {
	Status  int                      `json:"status,omitempty"`
	Headers map[string]string        `json:"headers,omitempty"`
	Body    string                   `json:"body,omitempty"`
	Paths   map[string]servePathSpec `json:"paths,omitempty"`
	TLS     bool                     `json:"tls,omitempty"`
}

// servePathSpec overrides the default response for one path: a zero status
// and a nil body inherit the default, headers are added to the default's.
type servePathSpec struct {
	Status  int               `json:"status,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    *string           `json:"body,omitempty"`
}

func validateServe(s *serveSpec) error {
	check := func(where string, status int, headers map[string]string) error {
		if status != 0 && (status < 200 || status > 599) {
			return fmt.Errorf("serve%s: status %d is not 200-599", where, status)
		}
		for k, v := range headers {
			if k == "" || strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
				return fmt.Errorf("serve%s: header %q has an empty name or a CR, LF or colon in its name or a CR or LF in its value", where, k)
			}
		}
		return nil
	}
	if len(s.Body) > maxServeBody {
		return fmt.Errorf("serve: body is over %d bytes", maxServeBody)
	}
	if len(s.Headers) > maxServeHeaders {
		return fmt.Errorf("serve: more than %d headers", maxServeHeaders)
	}
	if len(s.Paths) > maxServePaths {
		return fmt.Errorf("serve: more than %d paths", maxServePaths)
	}
	if err := check("", s.Status, s.Headers); err != nil {
		return err
	}
	for p, ps := range s.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("serve: path %q does not start with /", p)
		}
		if ps.Body != nil && len(*ps.Body) > maxServeBody {
			return fmt.Errorf("serve: body of %s is over %d bytes", p, maxServeBody)
		}
		if len(ps.Headers) > maxServeHeaders {
			return fmt.Errorf("serve: more than %d headers on %s", maxServeHeaders, p)
		}
		if err := check(" path "+p, ps.Status, ps.Headers); err != nil {
			return err
		}
	}
	return nil
}

func (s *serveSpec) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, body := s.Status, s.Body
		hdr := map[string]string{}
		for k, v := range s.Headers {
			hdr[k] = v
		}
		if ps, ok := s.Paths[r.URL.Path]; ok {
			if ps.Status != 0 {
				status = ps.Status
			}
			if ps.Body != nil {
				body = *ps.Body
			}
			for k, v := range ps.Headers {
				hdr[k] = v
			}
		}
		if status == 0 {
			status = http.StatusOK
		}
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(body))
		}
	})
}

// fixture is a loaded self-test fixture: its task with the placeholders
// substituted, the server that answers it (if it has a serve member), and
// the normalizer for the report it produces.
type fixture struct {
	Task tool.Task
	srv  *httptest.Server
	norm *fixtureNorm
}

// Close stops the fixture's server.
func (f *fixture) Close() {
	if f.srv != nil {
		f.srv.Close()
	}
}

// Normalize replaces the server's address in a normalized report by the
// placeholders, so the expect file is the same on every run.
func (f *fixture) Normalize(report []byte) ([]byte, error) {
	if f.norm == nil {
		return report, nil
	}
	return f.norm.apply(report)
}

var placeholderRE = regexp.MustCompile(`\{\{\s*fixture\.([A-Za-z0-9_]*)\s*\}\}`)

// substitute replaces the {{fixture.*}} placeholders of s; an unknown one is
// an error.
func substitute(s string, values map[string]string) (string, error) {
	var bad string
	out := placeholderRE.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholderRE.FindStringSubmatch(m)[1]
		v, ok := values[name]
		if !ok && bad == "" {
			bad = m
		}
		return v
	})
	if bad != "" {
		if len(values) == 0 {
			return "", fmt.Errorf("%s needs a serve member in the fixture", bad)
		}
		return "", fmt.Errorf("unknown placeholder %s (url, host, port and host_port exist)", bad)
	}
	return out, nil
}

// placeholderValues are the values of the placeholders for a server address.
func placeholderValues(scheme, host, port string) map[string]string {
	return map[string]string{
		"url": scheme + "://" + host + ":" + port, "host": host, "port": port, "host_port": host + ":" + port,
	}
}

// loadFixtureTask reads a fixture's task file. With a serve member it starts
// the loopback server and substitutes the placeholders of every target
// value; the caller closes the fixture.
func loadFixtureTask(dir string, f tool.Fixture) (*fixture, error) {
	raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(f.Task))) //nolint:gosec // a fixture path the manifest validated (relative, no ..)
	if err != nil {
		return nil, err
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Task, err)
	}
	var spec *serveSpec
	if sv, ok := members["serve"]; ok {
		delete(members, "serve")
		spec = &serveSpec{}
		d := json.NewDecoder(bytes.NewReader(sv))
		d.DisallowUnknownFields()
		if err := d.Decode(spec); err != nil {
			return nil, fmt.Errorf("%s: serve: %w", f.Task, err)
		}
		if err := validateServe(spec); err != nil {
			return nil, fmt.Errorf("%s: %w", f.Task, err)
		}
	}
	rest, err := json.Marshal(members)
	if err != nil {
		return nil, err
	}
	fx := &fixture{}
	d := json.NewDecoder(bytes.NewReader(rest))
	d.DisallowUnknownFields()
	if err := d.Decode(&fx.Task); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Task, err)
	}
	var values map[string]string
	if spec != nil {
		// Resolve every placeholder before a server starts.
		values = placeholderValues("http", "127.0.0.1", "0")
	}
	for i := range fx.Task.Targets {
		if _, err := substitute(fx.Task.Targets[i].Value, values); err != nil {
			return nil, fmt.Errorf("%s: target %q: %w", f.Task, fx.Task.Targets[i].Ref, err)
		}
	}
	if spec == nil {
		return fx, nil
	}
	srv := httptest.NewUnstartedServer(spec.handler())
	if !spec.TLS {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		srv.Listener = l
		srv.Start()
	} else {
		srv.StartTLS()
	}
	fx.srv = srv
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	scheme := "http"
	if spec.TLS {
		scheme = "https"
	}
	values = placeholderValues(scheme, "127.0.0.1", port)
	for i := range fx.Task.Targets {
		fx.Task.Targets[i].Value, _ = substitute(fx.Task.Targets[i].Value, values)
	}
	fx.norm = &fixtureNorm{url: values["url"], hostPort: values["host_port"]}
	return fx, nil
}

// fixtureNorm maps a server's actual address back to the placeholders.
type fixtureNorm struct{ url, hostPort string }

// apply rewrites the string values of a JSON report. It walks the decoded
// document, not the encoded bytes, so JSON escaping cannot hide a match.
func (n *fixtureNorm) apply(report []byte) ([]byte, error) {
	d := json.NewDecoder(bytes.NewReader(report))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(n.walk(v)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *fixtureNorm) walk(v any) any {
	switch x := v.(type) {
	case string:
		return n.str(x)
	case []any:
		for i := range x {
			x[i] = n.walk(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = n.walk(x[k])
		}
	}
	return v
}

func (n *fixtureNorm) str(s string) string {
	s = replaceBounded(s, n.url, "{{fixture.url}}")
	return replaceBounded(s, n.hostPort, "{{fixture.host_port}}")
}

// replaceBounded replaces old by repl where the match is not followed by a
// digit (so port 4321 does not match inside 43210).
func replaceBounded(s, old, repl string) string {
	var b strings.Builder
	for {
		i := strings.Index(s, old)
		if i < 0 {
			b.WriteString(s)
			return b.String()
		}
		end := i + len(old)
		b.WriteString(s[:i])
		if end < len(s) && s[end] >= '0' && s[end] <= '9' {
			b.WriteString(old)
		} else {
			b.WriteString(repl)
		}
		s = s[end:]
	}
}
