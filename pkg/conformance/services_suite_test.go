package conformance

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// detectFixture is a minimal credential-free detector of the fixtures (the
// reference a real tool is held to): it reads what the server sends first,
// tries a TLS handshake on a silent server, then a Redis PING, an HTTP GET
// and an LDAP search. With cred it also sends the credentials a careless
// tool would, so the sentinel has something to catch. It returns the CTIS
// service asset, or nil.
func detectFixture(value string, cred bool) map[string]any {
	hostport := strings.TrimSuffix(value, "/tcp")
	_, ps, _ := net.SplitHostPort(hostport)
	port, _ := strconv.Atoi(ps)
	svc := map[string]any{"port": port, "transport": "tcp"}
	asset := map[string]any{"type": "service", "value": value, "technical": map[string]any{"service": svc}}
	dial := func() net.Conn {
		c, err := net.DialTimeout("tcp", hostport, time.Second)
		if err != nil {
			return nil
		}
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		return c
	}
	c := dial()
	if c == nil {
		return nil
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	first := buf[:n]
	switch {
	case bytes.HasPrefix(first, []byte("SSH-")):
		svc["app_protocol"], svc["banner"] = "ssh", cleanText(string(first))
		if cred {
			cfg := &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("admin")},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 2 * time.Second} //nolint:gosec // a test of the sentinel
			if cl, err := ssh.Dial("tcp", hostport, cfg); err == nil {
				_ = cl.Close()
			}
		}
		return asset
	case bytes.HasPrefix(first, []byte("220")):
		svc["app_protocol"], svc["banner"] = "smtp", cleanText(string(first))
		_, _ = io.WriteString(c, "EHLO conformance.example\r\n")
		_, _ = c.Read(buf)
		if cred {
			_, _ = io.WriteString(c, "AUTH PLAIN AGFkbWluAGFkbWlu\r\n")
			_, _ = c.Read(buf)
		}
		return asset
	case len(first) > 5 && first[4] == 10:
		svc["app_protocol"] = "mysql"
		if cred {
			_, _ = c.Write(bytes.Repeat([]byte{1}, 40))
			time.Sleep(100 * time.Millisecond)
		}
		return asset
	case n == 0:
		tc := tls.Client(c, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}}) //nolint:gosec // loopback fixture
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if tc.Handshake() == nil {
			svc["app_protocol"], svc["is_tls"] = "https", true
			if cred {
				tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // loopback fixture
				req, _ := http.NewRequest(http.MethodGet, "https://"+hostport+"/", nil)       //nolint:noctx // test
				req.Header.Set("Authorization", "Basic YWRtaW46YWRtaW4=")
				if resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Do(req); err == nil {
					_ = resp.Body.Close()
				}
			}
			return asset
		}
	}
	probe := func(req []byte, ok func([]byte) bool) bool {
		pc := dial()
		if pc == nil {
			return false
		}
		defer func() { _ = pc.Close() }()
		if _, err := pc.Write(req); err != nil {
			return false
		}
		m, _ := pc.Read(buf)
		return ok(buf[:m])
	}
	authLine := ""
	if cred {
		authLine = "Authorization: Basic YWRtaW46YWRtaW4=\r\n"
	}
	switch {
	case probe([]byte("*1\r\n$4\r\nPING\r\n"), func(b []byte) bool {
		return bytes.HasPrefix(b, []byte("+PONG")) || bytes.HasPrefix(b, []byte("-NOAUTH"))
	}):
		svc["app_protocol"] = "redis"
		if cred {
			probe([]byte("*2\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n"), func([]byte) bool { return true })
		}
	case probe([]byte("GET / HTTP/1.1\r\nHost: "+hostport+"\r\n"+authLine+"Connection: close\r\n\r\n"), func(b []byte) bool { return bytes.HasPrefix(b, []byte("HTTP/1.")) }):
		svc["app_protocol"] = "http"
	case probe(ldapRootDSE, func(b []byte) bool { _, op, ok := ldapMessage(b); return ok && op == 0x65 }):
		svc["app_protocol"] = "ldap"
		if cred {
			// simple bind, cn=admin / admin
			probe([]byte{0x30, 0x1a, 0x02, 0x01, 0x02, 0x60, 0x15, 0x02, 0x01, 0x03, 0x04, 0x08, 'c', 'n', '=', 'a', 'd', 'm', 'i', 'n',
				0x80, 0x06, 'a', 'd', 'm', 'i', 'n', '!'}, func([]byte) bool { return true })
		}
	default:
		return nil
	}
	return asset
}

// ldapRootDSE is a base-scope search of the root DSE for objectClass.
var ldapRootDSE = []byte{0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04, 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00,
	0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's',
	0x30, 0x00}

// cleanText is what a careful tool reports as a banner.
func cleanText(v string) string {
	v = strings.ToValidUTF8(v, "")
	var b strings.Builder
	for _, r := range v {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			r = ' '
		}
		if b.Len()+utf8.RuneLen(r) > MaxServiceBanner {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// detectAll runs detectFixture on every target of a task.
func detectAll(task tool.Task, cred bool) (*ctis.Report, error) {
	var assets []map[string]any
	for _, t := range task.Targets {
		if a := detectFixture(t.Value, cred); a != nil {
			assets = append(assets, a)
		}
	}
	raw, err := json.Marshal(map[string]any{"version": "2.0", "metadata": map[string]any{"generated_at": "2026-01-01T00:00:00Z"}, "assets": assets})
	if err != nil {
		return nil, err
	}
	var rep ctis.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

// A credential-free detector passes the suite: no sentinel, every fixture
// identified, clean bounded strings (its SMTP banner is cleaned).
func TestDetectServicesSuite_CleanDetectorPasses(t *testing.T) {
	r := &suiteRecorder{}
	DetectServicesSuite(r, func(task tool.Task) (*ctis.Report, error) {
		if task.Capability != "detect.services@1" || len(task.Targets) != 7 || string(task.Params["depth"]) != `"thorough"` {
			t.Errorf("task %+v", task)
		}
		return detectAll(task, false)
	})
	if len(r.errs) > 0 {
		t.Fatalf("clean detector failed the suite:\n%s", strings.Join(r.errs, "\n"))
	}
}

// Every fixture catches the credentials a careless tool sends.
func TestDetectServicesSuite_SentinelCatchesCredentials(t *testing.T) {
	f, err := StartServiceFixtures()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := detectAll(tool.Task{Targets: f.Targets()}, true); err != nil {
		t.Fatal(err)
	}
	// The HTTP fixture is reached only by a tool that did not stop at an
	// earlier probe; send its credential directly too.
	req, _ := http.NewRequest(http.MethodPost, "http://"+strings.TrimSuffix(f.Value(FixtureHTTP), "/tcp")+"/", nil) //nolint:noctx // test
	req.Header.Set("Authorization", "Bearer x")
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
	// And the relay commands of an open-relay test.
	if c, err := net.Dial("tcp", strings.TrimSuffix(f.Value(FixtureSMTP), "/tcp")); err == nil {
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 2048)
		_, _ = c.Read(buf)
		_, _ = io.WriteString(c, "MAIL FROM:<a@example.com>\r\n")
		_, _ = c.Read(buf)
		_ = c.Close()
	}
	time.Sleep(200 * time.Millisecond)
	got := strings.Join(f.CredentialAttempts(), "\n")
	for _, want := range []string{
		"ssh: ", "smtp: AUTH", "smtp: MAIL", "mysql: the client answered", "tls: Authorization",
		"redis: AUTH", "http: Authorization", "http: \"POST\"", "ldap: bind",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("sentinel missed %q; recorded:\n%s", want, got)
		}
	}
	probs := f.Problems(&ctis.Report{})
	if len(probs) == 0 || !strings.HasPrefix(probs[0], "credential sentinel: ") {
		t.Errorf("problems do not lead with the sentinel: %v", probs)
	}
}

// What the tool reports is bounded and checked.
func TestDetectServicesSuite_OutputChecks(t *testing.T) {
	f, err := StartServiceFixtures()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rep, err := detectAll(tool.Task{Targets: f.Targets()}, false)
	if err != nil {
		t.Fatal(err)
	}
	details := map[string]string{"k": strings.Repeat("v", MaxServiceDetailValue+1)}
	for i := range MaxServiceDetails {
		details[fmt.Sprintf("d%d", i)] = "x"
	}
	for i := range rep.Assets {
		s := rep.Assets[i].Technical.Service
		switch rep.Assets[i].Value {
		case f.Value(FixtureSMTP):
			s.Banner = hostileSMTPGreeting // raw: too long, escapes, CR/LF, NUL, invalid UTF-8
		case f.Value(FixtureRedis):
			s.HasAnonymousAccess = true
		case f.Value(FixtureTLS):
			s.IsTLS = false
		case f.Value(FixtureSSH):
			s.AppProtocol = "telnet"
			s.Details = details
		}
	}
	rep.Assets = append(rep.Assets, ctis.Asset{Type: ctis.AssetTypeService, Value: "127.0.0.1:1/tcp",
		Technical: &ctis.AssetTechnical{Service: &ctis.ServiceTechnical{Port: 1, Transport: ctis.TransportTCP, AppProtocol: "x"}}})
	got := strings.Join(f.Problems(rep), "\n")
	for _, want := range []string{
		"smtp: banner is ", "smtp: banner is not valid UTF-8",
		"redis: reported has_anonymous_access", "tls: the TLS fixture was not reported with is_tls",
		`ssh: app_protocol "telnet"`, "ssh: 17 details", `ssh: details["k"] is 257 bytes`,
		`reported service "127.0.0.1:1/tcp", which it was not given`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing problem %q in:\n%s", want, got)
		}
	}
	// A valid string with a control character is caught too.
	if p := dirtyText("a\x1b[31mb"); !strings.Contains(p, "U+001B") {
		t.Errorf("escape not caught: %q", p)
	}
	if p := dirtyText("a\r\nb"); !strings.Contains(p, "U+000D") {
		t.Errorf("CR not caught: %q", p)
	}
	if p := dirtyText("café <b>"); p != "" {
		t.Errorf("clean text flagged: %q", p)
	}
	// A failed run: only the sentinel speaks.
	if p := f.Problems(nil); len(p) != 0 {
		t.Errorf("problems of a failed run: %v", p)
	}
}

const servicesTool = `tier: T1
implements: [{capability: detect.services@1}]
consumes: [service]
produces: [asset:service]
permissions: {network: targets}
run: {profile: exec, argv: [EXE, "{{task.targets_file}}"], output: {format: ctis, from: stdout}}
`

// The contract suite runs the detect.services suite on an exec tool.
func TestContractSuite_DetectServices(t *testing.T) {
	r := runContract(fakeManifest(t, servicesTool, nil), ContractOptions{Capability: true,
		Env: map[string]string{fakeToolEnv: "services"}, Timeout: 60 * time.Second})
	if len(r.errs) > 0 {
		t.Fatalf("credential-free tool failed:\n%s", strings.Join(r.errs, "\n"))
	}
	r = runContract(fakeManifest(t, servicesTool, nil), ContractOptions{Capability: true,
		Env: map[string]string{fakeToolEnv: "services-cred"}, Timeout: 60 * time.Second})
	if !hasErr(r, "credential sentinel: redis: AUTH") || !hasErr(r, "credential sentinel: ssh: password authentication") {
		t.Fatalf("a tool that sends credentials passed:\n%s", strings.Join(r.errs, "\n"))
	}
}
