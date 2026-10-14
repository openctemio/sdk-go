package core

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/ctis/outcome"
)

func byScannerPolicy(roots ...string) *ScanTargetPolicy {
	return &ScanTargetPolicy{AllowedRoots: roots, LookupIP: fakeLookup(testDNS), ByScanner: true}
}

// A network scanner's targets: host:port is checked on its host, never
// looked up whole; a name that does not resolve is refused (dotless too);
// only http and https URLs pass; private space needs the opt-in.
func TestScanTargetPolicy_ValidateNetworkTarget(t *testing.T) {
	ctx := context.Background()
	ok := []string{
		"8.8.8.8", "8.8.8.8:80", "104.17.85.188:80", "8.8.8.8:443",
		"[2001:4860:4860::8888]:443", "2001:4860:4860::8888",
		"example.com", "example.com:8443", "https://example.com:8443/x", "http://8.8.8.8/",
		"203.0.113.0/24",
	}
	for _, target := range ok {
		if err := byScannerPolicy().ValidateNetworkTarget(ctx, target); err != nil {
			t.Errorf("%s: %v", target, err)
		}
	}
	refused := map[string]string{
		"127.0.0.1:80":             RefusedTargetDenied,
		"169.254.169.254":          RefusedTargetDenied,
		"169.254.169.254:80":       RefusedTargetDenied,
		"http://169.254.169.254/":  RefusedTargetDenied,
		"[::1]:443":                RefusedTargetDenied,
		"[fd00:ec2::254]:80":       RefusedTargetDenied,
		"localhost:8080":           RefusedTargetDenied,
		"metadata.google.internal": RefusedTargetDenied,
		"100.64.0.1":               RefusedTargetDenied,
		"imds.attacker.test:80":    RefusedTargetDenied,
		"mixed.attacker.test":      RefusedTargetDenied,
		"10.0.0.0/8":               RefusedTargetDenied,
		"0.0.0.0/0":                RefusedTargetDenied,
		"10.1.2.3:22":              RefusedTargetDenied,
		"unresolvable.example.net": RefusedTargetUnresolvable,
		"gone.example.net:443":     RefusedTargetUnresolvable,
		"intranet":                 RefusedTargetUnresolvable,
		"/work/repo":               RefusedTargetUnresolvable,
		"gopher://example.com/":    RefusedTargetInvalid,
		"file:///etc/passwd":       RefusedTargetInvalid,
		"*.example.com":            RefusedTargetWildcard,
	}
	for target, reason := range refused {
		err := byScannerPolicy().ValidateNetworkTarget(ctx, target)
		if err == nil {
			t.Errorf("%s: want refused", target)
			continue
		}
		if got := refusedTargetOf(target, err).Reason; got != reason {
			t.Errorf("%s: reason %q, want %q (%v)", target, got, reason, err)
		}
	}

	// The opt-in opens RFC1918 and ULA space, never metadata or loopback.
	open := byScannerPolicy()
	open.AllowPrivate = true
	for _, target := range []string{"10.1.2.3:22", "intranet.corp.test", "192.168.1.10:8080"} {
		if err := open.ValidateNetworkTarget(ctx, target); err != nil {
			t.Errorf("allow private: %s: %v", target, err)
		}
	}
	for _, target := range []string{"169.254.169.254:80", "127.0.0.1", "[fd00:ec2::254]:80"} {
		if err := open.ValidateNetworkTarget(ctx, target); err == nil {
			t.Errorf("allow private: %s: want refused", target)
		}
	}
}

// Each target is checked by the scanner that receives it: a code scanner's
// path is confined to the roots (relative paths in the first root), a trivy
// image gets its registry host checked, and a network scanner never takes a
// path.
func TestScanTargetPolicy_ValidateFor(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, _ := filepath.EvalSymlinks(repo)
	p := byScannerPolicy(root)

	for _, c := range []struct{ scanner, target, want string }{
		{"semgrep", repo, resolved},
		{"semgrep", "repo", resolved},
		{"gitleaks", "repo", resolved}, // retired name of a code scanner
		{"trivy", "nginx:latest", "nginx:latest"},
		{"trivy-image", "ghcr.io/org/app:1", "ghcr.io/org/app:1"},
		{"semgrep", "https://example.com/org/repo.git", "https://example.com/org/repo.git"},
		{"httpx", "104.17.85.188:80", "104.17.85.188:80"},
		{"nuclei", "https://example.com/", "https://example.com/"},
	} {
		got, err := p.ValidateFor(ctx, c.scanner, c.target)
		if err != nil || got != c.want {
			t.Errorf("%s %s: got %q, %v; want %q", c.scanner, c.target, got, err, c.want)
		}
	}
	for _, c := range []struct{ scanner, target string }{
		{"semgrep", "/etc"},
		{"semgrep", filepath.Join(repo, "..", "..")},
		{"semgrep", "missing"},
		{"semgrep", "~/.ssh"},
		{"semgrep", "https://169.254.169.254/repo.git"},
		{"trivy", "10.0.0.5:5000/app:1"},
		{"trivy-image", "localhost:5000/app"},
		{"nuclei", repo},
		{"httpx", "-config=/tmp/x"},
		{"httpx", " example.com"},
		{"custom-tool", "unresolvable.example.net"},
	} {
		if got, err := p.ValidateFor(ctx, c.scanner, c.target); err == nil {
			t.Errorf("%s %s: accepted as %q", c.scanner, c.target, got)
		}
	}

	// Without ByScanner a target is read by its shape, as before.
	shape := newTestPolicy(root)
	if got, err := shape.ValidateFor(ctx, "nuclei", repo); err != nil || got != resolved {
		t.Errorf("shape policy: got %q, %v", got, err)
	}
}

// A scan whose targets mix a good one with loopback, an unresolvable name
// and the metadata address runs on the good one only; each refused target
// is listed with its reason and the guard rule and settled skipped/refused.
// A scan of refused targets only fails, naming them.
func TestDefaultCommandExecutor_GuardRefusesPerTarget(t *testing.T) {
	ctx := context.Background()
	bad := []string{"127.0.0.1:80", "gone.example.net:443", "169.254.169.254", "http://169.254.169.254/latest/"}
	sc := &listRecorder{}
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(byScannerPolicy())

	targets := append([]string{"104.17.85.188:80", "example.com:443"}, bad...)
	res, err := e.Execute(ctx, scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Targets: targets}))
	if err != nil {
		t.Fatalf("mixed targets: %v", err)
	}
	if !slices.Equal(sc.list, []string{"104.17.85.188:80", "example.com:443"}) {
		t.Fatalf("scanner got %v; want only the good targets", sc.list)
	}
	listed, _ := res.Metadata[MetaRefusedTargets].([]RefusedTarget)
	if len(listed) != len(bad) || res.Metadata[MetaRefusedTargetsTotal] != len(bad) || res.Metadata[MetaPartial] != true {
		t.Fatalf("refused metadata %+v", res.Metadata)
	}
	for i, r := range listed {
		if r.Target != bad[i] || r.Rule != RefusedTargetRuleGuard || r.Reason == "" || r.Detail == "" {
			t.Errorf("refused[%d] = %+v", i, r)
		}
	}
	if listed[1].Reason != RefusedTargetUnresolvable {
		t.Errorf("unresolvable target reason %q", listed[1].Reason)
	}
	got := map[string]outcome.Target{}
	for _, o := range res.TargetOutcomes {
		got[o.Target] = o
	}
	for _, b := range bad {
		if o := got[b]; o.State != outcome.Skipped || o.Class != outcome.Refused {
			t.Errorf("%s: outcome %+v; want skipped/refused", b, o)
		}
	}
	for _, g := range []string{"104.17.85.188:80", "example.com:443"} {
		if got[g].State != outcome.Done {
			t.Errorf("%s: outcome %+v; want done", g, got[g])
		}
	}

	sc2 := &listRecorder{}
	e2 := NewDefaultCommandExecutor(nil)
	e2.AddScanner(sc2)
	e2.SetScanTargetPolicy(byScannerPolicy())
	_, err = e2.Execute(ctx, scanCommand(t, ScanCommandPayload{Scanner: "nuclei", Targets: bad}))
	var rerr *refusedTargetsError
	if err == nil || !errors.As(err, &rerr) || len(rerr.refused) != len(bad) {
		t.Fatalf("all refused: err %v", err)
	}
	if !strings.Contains(err.Error(), "4 of 4 targets refused") || !strings.Contains(err.Error(), "gone.example.net") {
		t.Errorf("all refused: unclear reason %q", err)
	}
	if sc2.list != nil {
		t.Errorf("scanner ran on %v", sc2.list)
	}
}
