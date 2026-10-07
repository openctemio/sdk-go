package conformance

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The page title of the HTTP fixture.
const fixtureTitle = "openctem-conformance-fixture"

// capabilitySuite runs the active suite of one capability, or says that
// the capability is checked through the fixtures only.
func (r *contractRun) capabilitySuite(c capability.Capability) {
	name := "Capability/" + c.Ref()
	switch c.ID {
	case "scan.ports":
		r.scanPorts(name, c)
	case "probe.http":
		r.probeHTTP(name, c)
	case "vuln.templates":
		r.vulnTemplates(name, c)
	case "secrets.code":
		r.secretsCode(name, c)
	case "sast.code":
		r.codeRepo(name, c, map[string]string{
			"app.py": "import subprocess, sys\n\ndef run(cmd):\n    subprocess.call(cmd, shell=True)\n\neval(sys.argv[1])\n",
		}, func(out *toolhost.Outcome) string {
			if len(out.Report.Findings) == 0 {
				return "found nothing in a file with shell=True and eval of input"
			}
			return ""
		})
	case "sca.deps":
		r.codeRepo(name, c, map[string]string{
			"requirements.txt": "django==1.11.0\nrequests==2.19.0\n",
			"package.json":     `{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"4.17.4"}}` + "\n",
		}, func(out *toolhost.Outcome) string {
			if len(out.Report.Dependencies) == 0 && len(out.Report.Findings) == 0 {
				return "found no dependency in a repository with requirements.txt and package.json"
			}
			return ""
		})
	default:
		r.t.Logf("%s: no active suite (the tool cannot be pointed at a local fixture for it); checked through the fixtures' output only", name)
	}
}

// runSuite runs one suite task and checks the contract of its output.
func (r *contractRun) runSuite(name string, c capability.Capability, task tool.Task) *toolhost.Outcome {
	task.Capability = c.Ref()
	out, err := r.run(task)
	if err != nil {
		r.t.Errorf("%s: %v", name, err)
		return nil
	}
	if out.Status == tool.StatusFailed {
		r.t.Errorf("%s: the task failed: %v (stderr: %.300s)", name, out.Err, out.Stderr)
		return nil
	}
	if v, _ := c.Check(out.Report, capability.CheckOptions{Shape: outputShape(r.m, c)}); len(v) > 0 {
		r.t.Errorf("%s: %d record(s) miss the contract, first: %s", name, len(v), v[0])
	}
	return out
}

// scanPorts: two loopback ports open and one closed; the tool reports
// exactly the open ones.
func (r *contractRun) scanPorts(name string, c capability.Capability) {
	if !r.takes(c, "ports") {
		r.t.Errorf("%s: the tool does not take the standard param ports, so it cannot be told which ports to scan", name)
		return
	}
	a, err := listen("127.0.0.1:0")
	if err != nil {
		r.t.Errorf("%s: %v", name, err)
		return
	}
	defer a.close()
	b, err := listen("127.0.0.1:0")
	if err != nil {
		r.t.Errorf("%s: %v", name, err)
		return
	}
	defer b.close()
	closed := closedPort()
	target, ok := r.target([][2]string{{"ip_address", "127.0.0.1"}, {"host", "127.0.0.1"}, {"domain", "localhost"}, {"subdomain", "localhost"}})
	if !ok {
		r.t.Errorf("%s: the tool consumes none of ip_address, host, domain, subdomain", name)
		return
	}
	want := []int{a.port(), b.port()}
	slices.Sort(want)
	out := r.runSuite(name, c, tool.Task{Targets: []tool.Target{target},
		Params: map[string]json.RawMessage{"ports": strParam(joinInts(append(slices.Clone(want), closed)))}})
	if out == nil {
		return
	}
	if got := openPorts(out.Report); !slices.Equal(got, want) {
		r.t.Errorf("%s: reported open ports %v, want exactly %v (port %d is closed)", name, got, want, closed)
	}
}

// fixtureApp is an HTTP app with known issues: an exposed git config and
// environment file.
func fixtureApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/.git/config", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote \"origin\"]\n\turl = https://git.example/app.git\n"))
	})
	mux.HandleFunc("/.env", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("APP_ENV=production\nDB_PASSWORD=conformance-not-a-secret\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, "<html><head><title>%s</title></head><body>index</body></html>", fixtureTitle)
	})
	return httptest.NewServer(mux)
}

func urlTargets(u string) [][2]string {
	return [][2]string{{"http_service", u}, {"website", u}, {"web_application", u}, {"api", u}, {"discovered_url", u}}
}

// probeHTTP: a fixture page; the tool reports it with status 200.
func (r *contractRun) probeHTTP(name string, c capability.Capability) {
	srv := fixtureApp()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	task := tool.Task{}
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		target, ok = r.target([][2]string{{"ip_address", "127.0.0.1"}, {"host", "127.0.0.1"}, {"domain", "localhost"}, {"subdomain", "localhost"}})
		if !ok || !r.takes(c, "ports") {
			r.t.Errorf("%s: the tool takes no URL, and no host with the standard param ports", name)
			return
		}
		task.Params = map[string]json.RawMessage{"ports": strParam(port)}
	}
	task.Targets = []tool.Target{target}
	out := r.runSuite(name, c, task)
	if out == nil {
		return
	}
	found := false
	for _, a := range out.Report.Assets {
		if a.Type != ctis.AssetTypeHTTPService || !strings.Contains(a.Value, ":"+port) {
			continue
		}
		found = true
		if code, ok := a.Properties["status_code"].(float64); ok && code != 200 {
			r.t.Errorf("%s: status %v for the fixture page, want 200", name, code)
		}
		if title, ok := a.Properties["title"].(string); ok && title != "" && title != fixtureTitle {
			r.t.Errorf("%s: title %q, want %q", name, title, fixtureTitle)
		}
	}
	if !found {
		r.t.Errorf("%s: no http_service asset for the fixture %s", name, srv.URL)
	}
}

// vulnTemplates: an app with an exposed git config and .env; the tool
// reports at least one finding.
func (r *contractRun) vulnTemplates(name string, c capability.Capability) {
	srv := fixtureApp()
	defer srv.Close()
	target, ok := r.target(urlTargets(srv.URL))
	if !ok {
		r.t.Errorf("%s: the tool takes no URL target", name)
		return
	}
	out := r.runSuite(name, c, tool.Task{Targets: []tool.Target{target}})
	if out != nil && len(out.Report.Findings) == 0 {
		r.t.Errorf("%s: found nothing on a fixture app with an exposed /.git/config and /.env", name)
	}
}

// codeRepo runs a code capability on a fixture repository.
func (r *contractRun) codeRepo(name string, c capability.Capability, files map[string]string, check func(*toolhost.Outcome) string) *toolhost.Outcome {
	dir, err := os.MkdirTemp("", "openctem-conformance-repo-")
	if err != nil {
		r.t.Errorf("%s: %v", name, err)
		return nil
	}
	defer func() { _ = os.RemoveAll(dir) }()
	for f, content := range files {
		if err := os.WriteFile(filepath.Join(dir, f), []byte(content), 0o644); err != nil { //nolint:gosec // a fixture the tool must read
			r.t.Errorf("%s: %v", name, err)
			return nil
		}
	}
	target, ok := r.target([][2]string{{"repository", dir}})
	if !ok {
		r.t.Errorf("%s: the tool does not consume repository", name)
		return nil
	}
	out := r.runSuite(name, c, tool.Task{Targets: []tool.Target{target}})
	if out != nil && check != nil {
		if msg := check(out); msg != "" {
			r.t.Errorf("%s: %s", name, msg)
		}
	}
	return out
}

// randomToken is n random characters of the alphabet.
func randomToken(alphabet string, n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// secretsCode: a repository with two fresh fake credentials; the tool
// reports a secret finding with a masked value, and neither raw value
// appears anywhere in what the runtime keeps.
func (r *contractRun) secretsCode(name string, c capability.Capability) {
	aws := "AKIA" + randomToken("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 16)
	gh := "ghp_" + randomToken("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 36)
	files := map[string]string{
		"config.py": fmt.Sprintf("AWS_ACCESS_KEY_ID = %q\nGITHUB_TOKEN = %q\n", aws, gh),
	}
	out := r.codeRepo(name, c, files, nil)
	if out == nil {
		return
	}
	secrets := 0
	for _, f := range out.Report.Findings {
		if f.Type != ctis.FindingTypeSecret {
			continue
		}
		secrets++
		if f.Secret == nil || strings.TrimSpace(f.Secret.MaskedValue) == "" {
			r.t.Errorf("%s: secret finding %q has no masked value", name, f.RuleID)
		}
	}
	if secrets == 0 {
		r.t.Errorf("%s: found no secret in a file with an access key and a token", name)
	}
	raw, _ := json.Marshal(out.Report)
	all := string(raw) + out.Stderr + fmt.Sprint(out.Logs)
	for _, v := range []string{aws, gh} {
		if strings.Contains(all, v) {
			r.t.Errorf("%s: a raw secret value reached the report or the logs", name)
			break
		}
	}
}

// scope gives the tool target A while B listens on another loopback
// address; any connection to B fails.
func (r *contractRun) scope() {
	addr := r.opts.ScopeListenAddr
	if addr == "" {
		addr = "127.0.0.2:0"
	}
	b, err := listen(addr)
	if err != nil {
		r.t.Logf("Scope: cannot listen on %s (%v); skipped", addr, err)
		return
	}
	defer b.close()
	a, err := listen("127.0.0.1:0")
	if err != nil {
		r.t.Errorf("Scope: %v", err)
		return
	}
	defer a.close()
	srv := fixtureApp()
	defer srv.Close()
	cands := append(urlTargets(srv.URL), [][2]string{
		{"ip_address", "127.0.0.1"}, {"host", "127.0.0.1"}, {"domain", "localhost"}, {"subdomain", "localhost"},
		{"open_port", fmt.Sprintf("127.0.0.1:%d", a.port())},
	}...)
	target, ok := r.target(cands)
	if !ok {
		r.t.Logf("Scope: the tool takes no network target; skipped")
		return
	}
	task := tool.Task{Targets: []tool.Target{target}}
	if caps := r.m.ImplementedCapabilities(); len(caps) > 0 {
		task.Capability = caps[0].Ref()
		if r.takes(caps[0], "ports") {
			task.Params = map[string]json.RawMessage{"ports": strParam(fmt.Sprint(a.port()))}
		}
	}
	if _, err := r.run(task); err != nil {
		r.t.Errorf("Scope: %v", err)
		return
	}
	if n := b.accepted(); n > 0 {
		r.t.Errorf("Scope: the tool connected %d time(s) to %s, an address it was not given (target %s)", n, b.ln.Addr(), target.Value)
	}
}
