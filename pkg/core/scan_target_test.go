package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeLookup resolves from a fixed table; unknown names fail like NXDOMAIN.
func fakeLookup(table map[string][]string) func(context.Context, string) ([]net.IP, error) {
	return func(_ context.Context, host string) ([]net.IP, error) {
		addrs, ok := table[strings.ToLower(host)]
		if !ok {
			return nil, errors.New("no such host")
		}
		ips := make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, net.ParseIP(a))
		}
		return ips, nil
	}
}

var testDNS = map[string][]string{
	"example.com":          {"93.184.216.34"},
	"ghcr.io":              {"140.82.112.33"},
	"imds.attacker.test":   {"169.254.169.254"},
	"loop.attacker.test":   {"127.0.0.1"},
	"mixed.attacker.test":  {"93.184.216.34", "10.0.0.7"},
	"intranet.corp.test":   {"10.1.2.3"},
	"v6imds.attacker.test": {"fe80::1"},
	"awsv6.attacker.test":  {"fd00:ec2::254"},
}

func newTestPolicy(roots ...string) *ScanTargetPolicy {
	return &ScanTargetPolicy{AllowedRoots: roots, LookupIP: fakeLookup(testDNS)}
}

func TestScanTargetPolicy_NetworkTargets(t *testing.T) {
	cases := []struct {
		name         string
		target       string
		allowPrivate bool
		wantErr      bool
	}{
		// Attacks: must fail.
		{"imds url", "http://169.254.169.254/latest/meta-data/", false, true},
		{"imds url allow-private still blocked", "http://169.254.169.254/latest/meta-data/", true, true},
		{"imds bare ip", "169.254.169.254", false, true},
		{"gcp metadata alias", "http://metadata.google.internal/computeMetadata/v1/", false, true},
		{"loopback ip", "127.0.0.1", false, true},
		{"loopback url", "http://127.0.0.1:8080/admin", false, true},
		{"localhost", "localhost:6379", false, true},
		{"localhost subdomain", "http://foo.localhost/", false, true},
		{"ipv6 loopback", "http://[::1]:8080/", false, true},
		{"ipv6 unspecified", "::", false, true},
		{"ipv4 unspecified", "0.0.0.0", false, true},
		{"ipv6 multicast", "ff02::1", false, true},
		{"ipv4 multicast", "224.0.0.1", false, true},
		{"ipv6 link-local", "fe80::1", false, true},
		{"ipv4-mapped imds", "::ffff:169.254.169.254", false, true},
		{"cgnat", "100.64.0.1", false, true},
		// The IPv6 metadata endpoints sit inside the ULA range (fc00::/7),
		// which the allow-private opt-in opens; they must stay blocked.
		{"aws imds ipv6 allow-private still blocked", "http://[fd00:ec2::254]/latest/meta-data/", true, true},
		{"gcp metadata ipv6 allow-private still blocked", "fd20:ce::254", true, true},
		{"dns to aws imds ipv6 allow-private", "awsv6.attacker.test", true, true},
		{"cidr containing aws imds ipv6 allow-private", "fd00:ec2::/32", true, true},
		{"private by default", "10.0.0.5", false, true},
		{"private url by default", "https://192.168.1.10/", false, true},
		{"dns to imds", "http://imds.attacker.test/", false, true},
		{"dns to loopback", "loop.attacker.test", false, true},
		{"dns any record blocked", "mixed.attacker.test", false, true},
		{"dns to v6 link-local", "v6imds.attacker.test:443", false, true},
		{"dotted name that does not resolve", "http://nope.invalid/", false, true},
		{"cidr everything", "0.0.0.0/0", false, true},
		{"cidr containing imds", "169.0.0.0/8", false, true},
		{"cidr containing imds with allow-private", "169.254.0.0/16", true, true},
		{"cidr private by default", "10.0.0.0/24", false, true},
		{"cidr overlapping private", "8.0.0.0/4", false, true},
		{"file scheme", "file:///etc/passwd", false, true},
		{"file scheme no slashes", "file:/etc/passwd", false, true},
		{"gopher scheme", "gopher://example.com:70/", false, true},
		{"dict scheme", "dict://example.com:11211/", false, true},
		{"flag injection", "-config=/tmp/evil.yaml", false, true},
		{"flag injection long", "--help", false, true},
		{"newline injection", "example.com\n-o /tmp/x", false, true},
		{"nul byte", "example.com\x00", false, true},
		{"leading space", " example.com", false, true},
		{"empty", "", false, true},

		// Legitimate: must pass.
		{"public https url", "https://example.com/login", false, false},
		{"public host", "example.com", false, false},
		{"public host port", "example.com:8443", false, false},
		{"public ip", "8.8.8.8", false, false},
		{"public ipv6", "2606:4700:4700::1111", false, false},
		{"public cidr", "203.0.113.0/24", false, false},
		{"image ref name tag", "nginx:latest", false, false},
		{"image ref bare", "alpine", false, false},
		{"image ref registry", "ghcr.io/openctemio/sensor:v1", false, false},
		{"private with opt-in", "10.0.0.5", true, false},
		{"private url with opt-in", "https://192.168.1.10/", true, false},
		{"private dns with opt-in", "intranet.corp.test", true, false},
		{"private cidr with opt-in", "10.0.0.0/24", true, false},
		{"ula with opt-in", "fd00:ec2::253", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPolicy()
			p.AllowPrivate = tc.allowPrivate
			got, err := p.Validate(context.Background(), tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q) = %q, want error", tc.target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) unexpected error: %v", tc.target, err)
			}
			if got != tc.target {
				t.Errorf("Validate(%q) rewrote network target to %q", tc.target, got)
			}
		})
	}
}

func TestScanTargetPolicy_FilesystemConfinement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	repo := filepath.Join(root, "repo")
	outside := filepath.Join(base, "secrets")
	for _, d := range []string{repo, outside} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Symlink inside the root that points outside it.
	escapeLink := filepath.Join(root, "escape")
	if err := os.Symlink(outside, escapeLink); err != nil {
		t.Fatal(err)
	}
	// Symlink inside the root that stays inside it.
	innerLink := filepath.Join(root, "repo-link")
	if err := os.Symlink(repo, innerLink); err != nil {
		t.Fatal(err)
	}
	resolvedRepo, _ := filepath.EvalSymlinks(repo)

	cases := []struct {
		name    string
		target  string
		want    string
		wantErr bool
	}{
		{"repo inside root", repo, resolvedRepo, false},
		{"root itself", root, "", false},
		{"symlink staying inside", innerLink, resolvedRepo, false},
		{"symlink escaping root", escapeLink, "", true},
		{"dotdot escape", filepath.Join(repo, "..", "..", "secrets"), "", true},
		{"outside root", outside, "", true},
		{"system path", "/etc", "", true},
		{"filesystem root", "/", "", true},
		{"nonexistent", filepath.Join(root, "missing"), "", true},
		{"tilde", "~/.ssh", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := newTestPolicy(root).Validate(context.Background(), tc.target)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Validate(%q) = %q, want error", tc.target, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Validate(%q) unexpected error: %v", tc.target, err)
			}
			if tc.want != "" && got != tc.want {
				t.Errorf("Validate(%q) = %q, want %q", tc.target, got, tc.want)
			}
		})
	}
}

func TestScanTargetPolicy_FilesystemNoRoots(t *testing.T) {
	dir := t.TempDir()
	p := newTestPolicy() // no AllowedRoots: denylist mode

	if _, err := p.Validate(context.Background(), dir); err != nil {
		t.Errorf("ordinary directory rejected without roots: %v", err)
	}
	for _, bad := range []string{"/", "/etc", "/proc/self", "/root"} {
		if _, err := os.Lstat(bad); err != nil {
			continue // not present on this host
		}
		if got, err := p.Validate(context.Background(), bad); err == nil {
			t.Errorf("Validate(%q) = %q, want error", bad, got)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		ssh := filepath.Join(home, ".ssh")
		if _, err := os.Stat(ssh); err == nil {
			if _, err := p.Validate(context.Background(), ssh); err == nil {
				t.Errorf("Validate(~/.ssh) accepted")
			}
		}
	}
	// Symlink to a sensitive dir is resolved before the check.
	link := filepath.Join(dir, "etc-link")
	if err := os.Symlink("/etc", link); err == nil {
		if got, err := p.Validate(context.Background(), link); err == nil {
			t.Errorf("symlink to /etc accepted as %q", got)
		}
	}
}

func TestScanTargetPolicy_DisabledAndDefault(t *testing.T) {
	p := &ScanTargetPolicy{Disabled: true}
	if got, err := p.Validate(context.Background(), "-anything"); err != nil || got != "-anything" {
		t.Errorf("disabled policy should pass through, got %q, %v", got, err)
	}

	t.Setenv(EnvScanRoots, "/a"+string(filepath.ListSeparator)+"/b")
	t.Setenv(EnvAllowPrivateTargets, "1")
	d := DefaultScanTargetPolicy()
	if len(d.AllowedRoots) != 2 || d.AllowedRoots[0] != "/a" || d.AllowedRoots[1] != "/b" {
		t.Errorf("AllowedRoots from env = %v", d.AllowedRoots)
	}
	if !d.AllowPrivate {
		t.Errorf("AllowPrivate should follow %s", EnvAllowPrivateTargets)
	}
}

// recordingScanner records the target it was asked to scan.
type recordingScanner struct {
	mu      sync.Mutex
	calls   int
	target  string
	options *ScanOptions
}

func (s *recordingScanner) Name() string           { return "rec" }
func (s *recordingScanner) Version() string        { return "1" }
func (s *recordingScanner) Capabilities() []string { return nil }
func (s *recordingScanner) IsInstalled(context.Context) (bool, string, error) {
	return true, "1", nil
}
func (s *recordingScanner) Scan(_ context.Context, target string, opts *ScanOptions) (*ScanResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	s.target = target
	s.options = opts
	return &ScanResult{ScannerName: "rec"}, nil
}

func scanCommand(t *testing.T, payload ScanCommandPayload) *Command {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	return &Command{ID: "c1", Type: "scan", Payload: raw}
}

// The executor must validate the server-supplied target before the scanner
// ever sees it.
func TestDefaultCommandExecutor_ValidatesScanTarget(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	resolvedRepo, _ := filepath.EvalSymlinks(repo)

	attacks := []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"127.0.0.1",
		"-config=/tmp/evil.yaml",
		"/etc",
		filepath.Join(repo, "..", ".."),
		"file:///etc/shadow",
	}
	for _, target := range attacks {
		t.Run("reject "+target, func(t *testing.T) {
			sc := &recordingScanner{}
			e := NewDefaultCommandExecutor(nil)
			e.AddScanner(sc)
			e.SetScanTargetPolicy(newTestPolicy(root))
			_, err := e.Execute(context.Background(), scanCommand(t, ScanCommandPayload{Scanner: "rec", Target: target}))
			if err == nil {
				t.Fatalf("target %q accepted", target)
			}
			if sc.calls != 0 {
				t.Fatalf("scanner invoked for rejected target %q", target)
			}
		})
	}

	t.Run("accept repo path", func(t *testing.T) {
		sc := &recordingScanner{}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(newTestPolicy(root))
		if _, err := e.Execute(context.Background(), scanCommand(t, ScanCommandPayload{Scanner: "rec", Target: repo})); err != nil {
			t.Fatalf("legit target rejected: %v", err)
		}
		if sc.calls != 1 || sc.target != resolvedRepo || sc.options.TargetDir != resolvedRepo {
			t.Errorf("scanner got target=%q dir=%q, want %q", sc.target, sc.options.TargetDir, resolvedRepo)
		}
	})

	t.Run("accept public url", func(t *testing.T) {
		sc := &recordingScanner{}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(newTestPolicy(root))
		if _, err := e.Execute(context.Background(), scanCommand(t, ScanCommandPayload{Scanner: "rec", Target: "https://example.com"})); err != nil {
			t.Fatalf("legit target rejected: %v", err)
		}
		if sc.target != "https://example.com" {
			t.Errorf("scanner got %q", sc.target)
		}
	})

	t.Run("reject flag-like exclude", func(t *testing.T) {
		sc := &recordingScanner{}
		e := NewDefaultCommandExecutor(nil)
		e.AddScanner(sc)
		e.SetScanTargetPolicy(newTestPolicy(root))
		cmd := scanCommand(t, ScanCommandPayload{
			Scanner: "rec", Target: repo,
			Config: map[string]interface{}{"exclude": []interface{}{"--config=/tmp/x"}},
		})
		if _, err := e.Execute(context.Background(), cmd); err == nil || sc.calls != 0 {
			t.Fatalf("flag-like exclude accepted (err=%v calls=%d)", err, sc.calls)
		}
	})
}
