package source

import (
	"context"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ctissource "github.com/openctemio/ctis/source"
)

// gitServer serves bare repositories under a temp root over HTTPS with git
// http-backend. The certificate is for example.com; Resolve points that name
// at the server.
type gitServer struct {
	srv    *httptest.Server
	root   string
	caFile string
	port   string
}

func newGitServer(t *testing.T, wrap func(http.Handler) http.Handler) *gitServer {
	t.Helper()
	gitBin, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	root := t.TempDir()
	var h http.Handler = &cgi.Handler{Path: gitBin, Args: []string{"http-backend"},
		Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	if wrap != nil {
		h = wrap(h)
	}
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(srv.URL)
	return &gitServer{srv: srv, root: root, caFile: ca, port: u.Port()}
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo creates acme/api.git with one commit holding files and a symlink to
// /etc/passwd, and returns that commit.
func (s *gitServer) repo(t *testing.T, files map[string]string) string {
	t.Helper()
	work := t.TempDir()
	git(t, work, "init", "-q", "-b", "main")
	for name, body := range files {
		p := filepath.Join(work, name)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(work, "escape")); err != nil {
		t.Fatal(err)
	}
	git(t, work, "add", "-A")
	git(t, work, "commit", "-q", "-m", "x")
	bare := filepath.Join(s.root, "acme", "api.git")
	_ = os.MkdirAll(filepath.Dir(bare), 0o755)
	git(t, s.root, "clone", "-q", "--bare", work, bare)
	git(t, bare, "config", "uploadpack.allowAnySHA1InWant", "true")
	return git(t, work, "rev-parse", "HEAD")
}

func (s *gitServer) fetcher(t *testing.T) *Fetcher {
	return &Fetcher{Root: t.TempDir(), CAFile: s.caFile, allowLoopback: true, Timeout: time.Minute,
		Resolve: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("127.0.0.1")}, nil }}
}

func (s *gitServer) source(commit string) ctissource.Repository {
	return ctissource.Repository{Kind: ctissource.KindGit, CloneURL: "https://example.com:" + s.port + "/acme/api.git",
		Branch: "main", Commit: commit, Capabilities: []string{"sast.code@1"}}
}

func TestFetchExactCommit(t *testing.T) {
	s := newGitServer(t, nil)
	commit := s.repo(t, map[string]string{"app.py": "print(1)\n", ".gitmodules": "[submodule \"x\"]\n\tpath = x\n\turl = https://example.com/evil.git\n"})
	f := s.fetcher(t)
	co, err := f.Fetch(context.Background(), s.source(commit), nil)
	if err != nil {
		t.Fatal(err)
	}
	if co.Commit != commit {
		t.Fatalf("commit %s", co.Commit)
	}
	if b, err := os.ReadFile(filepath.Join(co.Dir, "app.py")); err != nil || string(b) != "print(1)\n" {
		t.Fatalf("app.py: %q %v", b, err)
	}
	// A symbolic link is checked out as a plain file holding its target.
	fi, err := os.Lstat(filepath.Join(co.Dir, "escape"))
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("symlink checked out as a link: %v %v", fi.Mode(), err)
	}
	// The submodule was not fetched.
	if _, err := os.Stat(filepath.Join(co.Dir, "x", ".git")); err == nil {
		t.Fatal("submodule fetched")
	}
	info, _ := os.Stat(filepath.Dir(co.Dir))
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("checkout directory mode %v", info.Mode().Perm())
	}
	if err := co.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(co.Dir); !os.IsNotExist(err) {
		t.Fatal("checkout not removed")
	}
}

func TestFetchUnknownCommitFails(t *testing.T) {
	s := newGitServer(t, nil)
	s.repo(t, map[string]string{"a": "b"})
	f := s.fetcher(t)
	if _, err := f.Fetch(context.Background(), s.source(strings.Repeat("ab", 20)), nil); err == nil {
		t.Fatal("fetched a commit the repository does not have")
	}
	if entries, _ := os.ReadDir(f.Root); len(entries) != 0 {
		t.Fatalf("a failed fetch left %d directories", len(entries))
	}
}

func TestFetchCredentialStaysInTheHeader(t *testing.T) {
	const token = "ghs_secretTokenValue0123456789"
	var sawAuth bool
	s := newGitServer(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, p, ok := r.BasicAuth()
			if !ok || u != "x-access-token" || p != token {
				w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			sawAuth = true
			next.ServeHTTP(w, r)
		})
	})
	commit := s.repo(t, map[string]string{"a": "b"})
	f := s.fetcher(t)
	_, err := f.Fetch(context.Background(), s.source(commit), nil)
	if err == nil {
		t.Fatal("fetched without the credential")
	}
	co, err := f.Fetch(context.Background(), s.source(commit), &Credential{Username: "x-access-token", Password: token})
	if err != nil || !sawAuth {
		t.Fatalf("fetch with credential: %v (auth seen %v)", err, sawAuth)
	}
	// Nothing in the checkout holds the token (no credential store, no
	// remote URL with user information).
	_ = filepath.WalkDir(filepath.Dir(co.Dir), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			if b, _ := os.ReadFile(p); strings.Contains(string(b), token) {
				t.Errorf("token written to %s", p)
			}
		}
		return nil
	})
}

func TestFetchRefusesUnsafeHosts(t *testing.T) {
	for name, ip := range map[string]string{"metadata": "169.254.169.254", "loopback": "127.0.0.1", "private": "10.1.2.3"} {
		f := &Fetcher{Root: t.TempDir(), Resolve: func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP(ip)}, nil
		}}
		_, err := f.Fetch(context.Background(), ctissource.Repository{Kind: "git", CloneURL: "https://git.example.com/a/b",
			Branch: "main", Commit: strings.Repeat("a", 40), Capabilities: []string{"sast.code@1"}}, nil)
		if !errors.Is(err, ErrHostRefused) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// An internal SCM on a private address is allowed when the operator says so.
	f := &Fetcher{Root: t.TempDir(), AllowPrivate: true, Git: "/nonexistent/git",
		Resolve: func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.1.2.3")}, nil }}
	if _, err := f.Fetch(context.Background(), ctissource.Repository{Kind: "gitlab", CloneURL: "https://git.corp.example/a/b",
		Branch: "main", Commit: strings.Repeat("a", 40), Capabilities: []string{"sast.code@1"}}, nil); errors.Is(err, ErrHostRefused) {
		t.Errorf("private SCM refused with AllowPrivate: %v", err)
	}
}

func TestFetchRefusesAnInvalidSource(t *testing.T) {
	f := &Fetcher{Root: t.TempDir()}
	_, err := f.Fetch(context.Background(), ctissource.Repository{Kind: "git", CloneURL: "ext::sh -c id",
		Branch: "main", Commit: strings.Repeat("a", 40), Capabilities: []string{"sast.code@1"}}, nil)
	if !errors.Is(err, ctissource.ErrInvalid) {
		t.Fatalf("%v", err)
	}
}

func TestFetchDoesNotFollowRedirects(t *testing.T) {
	s := newGitServer(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://elsewhere.example"+r.URL.Path, http.StatusFound)
		})
	})
	commit := s.repo(t, map[string]string{"a": "b"})
	if _, err := s.fetcher(t).Fetch(context.Background(), s.source(commit), &Credential{Username: "u", Password: "p"}); err == nil {
		t.Fatal("followed a redirect")
	}
}

func TestFetchStopsAtMaxBytes(t *testing.T) {
	s := newGitServer(t, nil)
	commit := s.repo(t, map[string]string{"big.bin": strings.Repeat("0123456789abcdef", 1<<16)}) // 1 MiB
	f := s.fetcher(t)
	f.MaxBytes = 64 << 10
	if _, err := f.Fetch(context.Background(), s.source(commit), nil); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("%v", err)
	}
}

func TestGitEnvHasNoInheritedConfiguration(t *testing.T) {
	env := strings.Join(gitEnv("/w/repo", "/w/home", "https://example.com/a/b", "example.com:443:1.2.3.4", "", "", &Credential{Username: "u", Password: "tok"}), "\n")
	for _, want := range []string{"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "protocol.allow", "core.hooksPath",
		"http.followRedirects", "transfer.fsckObjects", "http.https://example.com/a/b.extraHeader", "example.com:443:1.2.3.4"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(env, "tok\n") || strings.Contains(env, ":tok") {
		t.Error("the credential is in clear text in the environment")
	}
}
