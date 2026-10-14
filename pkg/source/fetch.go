// Package source fetches the code of a platform code scan: exactly one
// commit of one repository (ctis source.Repository), read-only, into a
// private directory a scanner then reads. It is the one fetch mechanism for
// every sensor and collector, so the hardening lives in one place.
//
// The repository is untrusted. The fetch:
//   - speaks HTTPS only (every other git transport is off) to the host the
//     platform named, pinned to an address the SSRF guard accepted (no DNS
//     rebinding between the check and git's own lookup), without following
//     redirects;
//   - runs no repository code: no hooks, no submodules, no filters (LFS,
//     smudge/clean), no system or global git configuration;
//   - checks out symbolic links as plain files, so nothing in the checkout
//     points outside it;
//   - verifies every object it receives (transfer.fsckObjects) and that the
//     checkout is the requested commit;
//   - is bounded in time and in bytes on disk.
//
// A credential (a short-lived token the platform minted for this one
// repository) reaches git only through its environment as an HTTP header
// scoped to the clone URL, never in argv (visible to every local user) or a
// file in the checkout, and never reaches a scanner.
//
// Stability: Beta (docs/STABILITY.md).
package source

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	ctissource "github.com/openctemio/ctis/source"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Defaults.
const (
	DefaultTimeout  = 10 * time.Minute
	DefaultMaxBytes = int64(2) << 30 // 2 GiB on disk
	sizeCheckEvery  = 2 * time.Second
)

// Errors.
var (
	// ErrTooLarge: the checkout grew past MaxBytes; the fetch was stopped.
	ErrTooLarge = errors.New("source: repository is larger than the fetch limit")
	// ErrHostRefused: the clone host resolves to an address the SSRF guard
	// refuses (or does not resolve).
	ErrHostRefused = errors.New("source: clone host refused")
	// ErrWrongCommit: the checkout is not the requested commit.
	ErrWrongCommit = errors.New("source: checkout is not the requested commit")
)

// Credential authenticates the fetch (HTTP basic). For a GitHub App
// installation token the username is "x-access-token"; for a GitLab token
// "oauth2".
type Credential struct {
	Username string
	Password string
}

// Fetcher fetches repositories under Root.
type Fetcher struct {
	// Root is the directory checkouts are created in (the sensor's scan
	// workspace, so scanners may read them). Required.
	Root string
	// Git is the git binary; "" looks it up on PATH.
	Git string
	// Timeout bounds one fetch (DefaultTimeout when zero).
	Timeout time.Duration
	// MaxBytes bounds the checkout on disk (DefaultMaxBytes when zero).
	MaxBytes int64
	// AllowPrivate lets the clone host resolve to a private address
	// (RFC 1918, ULA): an internal SCM reached by the tenant's own sensor.
	// Loopback, link-local (cloud metadata), CGNAT and reserved ranges are
	// always refused.
	AllowPrivate bool
	// Proxy, when set, is passed to git as its HTTPS proxy; the proxy then
	// resolves the host and the address pin is not used.
	Proxy string
	// CAFile is a PEM bundle to trust for the SCM's certificate (an
	// internal SCM with a private CA); "" uses the system roots.
	CAFile string
	// Resolve looks up the clone host (net.DefaultResolver when nil).
	Resolve func(ctx context.Context, host string) ([]net.IP, error)
	// allowLoopback is for tests against a local server.
	allowLoopback bool
}

// Checkout is a fetched commit.
type Checkout struct {
	// Dir holds the working tree (and its .git directory).
	Dir string
	// Commit is the checked-out commit.
	Commit string
	root   string
}

// Remove deletes the checkout.
func (c *Checkout) Remove() error {
	if c == nil || c.root == "" {
		return nil
	}
	return os.RemoveAll(c.root)
}

// Fetch validates repo, fetches exactly repo.Commit and checks it out. The
// caller removes the checkout when the scan is done.
func (f *Fetcher) Fetch(ctx context.Context, repo ctissource.Repository, cred *Credential) (*Checkout, error) {
	if err := repo.Validate(); err != nil {
		return nil, err
	}
	if f.Root == "" {
		return nil, errors.New("source: no fetch root")
	}
	gitBin := f.Git
	if gitBin == "" {
		p, err := exec.LookPath("git")
		if err != nil {
			return nil, fmt.Errorf("source: git is not installed: %w", err)
		}
		gitBin = p
	}
	timeout, maxBytes := f.Timeout, f.MaxBytes
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	u, err := url.Parse(repo.CloneURL)
	if err != nil {
		return nil, err
	}
	pin := ""
	if f.Proxy == "" {
		ip, err := f.safeAddress(ctx, u.Hostname())
		if err != nil {
			return nil, err
		}
		port := u.Port()
		if port == "" {
			port = "443"
		}
		pin = u.Hostname() + ":" + port + ":" + ip.String()
	}

	root, err := os.MkdirTemp(f.Root, "src-")
	if err != nil {
		return nil, fmt.Errorf("source: create checkout directory: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = os.RemoveAll(root)
		}
	}()
	if err := os.Chmod(root, 0o700); err != nil { // #nosec G302 -- a directory: owner only
		return nil, err
	}
	dir := filepath.Join(root, "repo")
	home := filepath.Join(root, "home")
	for _, d := range []string{dir, home} {
		if err := os.Mkdir(d, 0o700); err != nil {
			return nil, err
		}
	}
	env := gitEnv(dir, home, repo.CloneURL, pin, f.Proxy, f.CAFile, cred)
	run := func(args ...string) (string, error) {
		return runGit(ctx, gitBin, dir, env, args...)
	}

	// The size watch stops a repository (or a crafted pack) that would fill
	// the disk before the fetch finishes.
	var tooLarge atomic.Bool
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go func() {
		t := time.NewTicker(sizeCheckEvery)
		defer t.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-t.C:
				if dirSize(root) > maxBytes {
					tooLarge.Store(true)
					cancel()
					return
				}
			}
		}
	}()

	steps := [][]string{
		{"init", "--quiet"},
		{"fetch", "--quiet", "--no-tags", "--no-recurse-submodules", "--depth", fmt.Sprint(repo.Depth), "--", repo.CloneURL, repo.Commit},
		{"checkout", "--quiet", "--detach", repo.Commit},
	}
	for _, args := range steps {
		if _, err := run(args...); err != nil {
			if tooLarge.Load() {
				return nil, ErrTooLarge
			}
			return nil, fmt.Errorf("source: git %s: %w", args[0], err)
		}
	}
	head, err := run("rev-parse", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("source: git rev-parse: %w", err)
	}
	if strings.TrimSpace(head) != repo.Commit {
		return nil, ErrWrongCommit
	}
	stopWatch()
	if dirSize(root) > maxBytes {
		return nil, ErrTooLarge
	}
	ok = true
	return &Checkout{Dir: dir, Commit: repo.Commit, root: root}, nil
}

// safeAddress resolves host and returns the first address the SSRF guard
// accepts; every address must be acceptable (a name that also resolves to a
// metadata or loopback address is refused outright).
func (f *Fetcher) safeAddress(ctx context.Context, host string) (net.IP, error) {
	resolve := f.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, h string) ([]net.IP, error) {
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, h)
			ips := make([]net.IP, 0, len(addrs))
			for _, a := range addrs {
				ips = append(ips, a.IP)
			}
			return ips, err
		}
	}
	ips, err := resolve(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s does not resolve", ErrHostRefused, host)
	}
	for _, ip := range ips {
		if httpsec.IsIPBlockedWith(ip, f.AllowPrivate, f.allowLoopback) {
			return nil, fmt.Errorf("%w: %s resolves to a refused address", ErrHostRefused, host)
		}
	}
	return ips[0], nil
}

// gitEnv is git's whole environment: nothing is inherited from the process
// (no credential helper, no global configuration, no askpass). Settings are
// command-scoped configuration (GIT_CONFIG_COUNT), never argv.
func gitEnv(dir, home, cloneURL, pin, proxy, caFile string, cred *Credential) []string {
	cfg := [][2]string{
		{"protocol.allow", "never"},
		{"protocol.https.allow", "always"},
		{"core.hooksPath", os.DevNull},
		{"core.symlinks", "false"},
		{"core.fsmonitor", "false"},
		{"core.askPass", ""},
		{"credential.helper", ""},
		{"submodule.recurse", "false"},
		{"fetch.recurseSubmodules", "false"},
		{"transfer.fsckObjects", "true"},
		{"http.followRedirects", "false"},
		{"init.defaultBranch", "scan"},
		{"advice.detachedHead", "false"},
		{"safe.directory", dir},
	}
	if pin != "" {
		cfg = append(cfg, [2]string{"http.curloptResolve", pin})
	}
	if caFile != "" {
		cfg = append(cfg, [2]string{"http.sslCAInfo", caFile})
	}
	if cred != nil && cred.Password != "" {
		basic := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
		// Scoped to the clone URL: sent to that URL's requests only.
		cfg = append(cfg, [2]string{"http." + cloneURL + ".extraHeader", "Authorization: Basic " + basic})
	}
	env := []string{
		"HOME=" + home,
		"PATH=/usr/bin:/bin:/usr/local/bin",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ALLOW_PROTOCOL=https",
		fmt.Sprintf("GIT_CONFIG_COUNT=%d", len(cfg)),
	}
	for i, kv := range cfg {
		env = append(env, fmt.Sprintf("GIT_CONFIG_KEY_%d=%s", i, kv[0]), fmt.Sprintf("GIT_CONFIG_VALUE_%d=%s", i, kv[1]))
	}
	if proxy != "" {
		env = append(env, "HTTPS_PROXY="+proxy)
	}
	return env
}

func runGit(ctx context.Context, gitBin, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, gitBin, append([]string{"-C", dir}, args...)...) // #nosec G204 -- fixed git subcommands; URL, branch and commit validated by ctis source
	cmd.Env = env
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &limited{w: &stderr, n: 4096}
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, redactAuth(strings.TrimSpace(stderr.String())))
	}
	return string(out), nil
}

// redactAuth removes an Authorization header value git might echo with
// GIT_TRACE-style output.
func redactAuth(s string) string {
	if i := strings.Index(strings.ToLower(s), "authorization:"); i >= 0 {
		return s[:i] + "authorization: [redacted]"
	}
	return s
}

type limited struct {
	w *strings.Builder
	n int
}

func (l *limited) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}

// dirSize sums the sizes of the regular files under root.
func dirSize(root string) int64 {
	var n int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil && info.Mode().IsRegular() {
			n += info.Size()
		}
		return nil
	})
	return n
}
