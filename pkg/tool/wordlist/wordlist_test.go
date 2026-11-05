package wordlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		purpose, in, want string
		ok                bool
	}{
		{DNSLabels, "WWW", "www", true},
		{DNSLabels, "api-v2.eu", "api-v2.eu", true},
		{DNSLabels, "*.corp", "", false},
		{DNSLabels, "_dmarc", "", false},
		{DNSLabels, "-bad", "", false},
		{DNSLabels, "a.b.c.d", "", false},
		{DNSLabels, strings.Repeat("a", 64), "", false},
		{DNSLabels, "bücher", "", false},
		{WebPaths, "/admin/", "admin/", true},
		{WebPaths, "//a/b", "a/b", true},
		{WebPaths, "http://evil.example/x", "", false},
		{WebPaths, "a/../etc/passwd", "", false},
		{WebPaths, "has space", "", false},
		{WebPaths, "# comment", "", false},
		{WebPaths, "a\x00b", "", false},
		{WebFiles, ".git/config\r", ".git/config", true},
		{APIRoutes, strings.Repeat("a/", 17), "", false},
		{Params, "user[id]", "user[id]", true},
		{Params, "a b", "", false},
		{Params, strings.Repeat("p", 65), "", false},
		{Extension, ".php", ".php", true},
		{Extension, "ph p", "", false},
		{"", "anything", "anything", true},
		{WebPaths, "", "", false},
	}
	for _, c := range cases {
		got, ok := Normalize(c.purpose, c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("Normalize(%q, %q) = %q, %v; want %q, %v", c.purpose, c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestComposeRankDedupAndCaps(t *testing.T) {
	generated := strings.NewReader("Staging\nvpn\nwww\n")
	pack := strings.NewReader("www\nmail\n\nvpn\n*.bad\nftp")
	var out bytes.Buffer
	res, err := Compose(&out, Options{Purpose: DNSLabels}, generated, nil, pack)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := out.String(), "staging\nvpn\nwww\nmail\nftp\n"; got != want {
		t.Fatalf("list %q, want %q", got, want)
	}
	sum := sha256.Sum256(out.Bytes())
	if res.Lines != 5 || res.Duplicates != 2 || res.Invalid != 1 || res.Truncated || res.SHA256 != hex.EncodeToString(sum[:]) || res.Bytes != int64(out.Len()) {
		t.Fatalf("result %+v", res)
	}

	out.Reset()
	res, err = Compose(&out, Options{Purpose: DNSLabels, MaxLines: 2}, strings.NewReader("a\nb\nc\nd\n"))
	if err != nil || !res.Truncated || out.String() != "a\nb\n" {
		t.Fatalf("capped: %q %+v %v", out.String(), res, err)
	}
	out.Reset()
	res, err = Compose(&out, Options{Purpose: DNSLabels, MaxBytes: 6}, strings.NewReader("aa\nbb\ncc\n"))
	if err != nil || !res.Truncated || out.String() != "aa\nbb\n" {
		t.Fatalf("byte cap: %q %+v %v", out.String(), res, err)
	}
}

func TestComposeOverlongLineAndEmpty(t *testing.T) {
	long := strings.Repeat("a", 3*MaxLineBytes)
	var out bytes.Buffer
	res, err := Compose(&out, Options{Purpose: WebPaths}, strings.NewReader("ok\n"+long+"\nafter\n"+long))
	if err != nil || out.String() != "ok\nafter\n" || res.Invalid != 2 {
		t.Fatalf("%q %+v %v", out.String(), res, err)
	}
	out.Reset()
	if _, err := Compose(&out, Options{Purpose: Params}, strings.NewReader("a b\n#x\n")); !errors.Is(err, ErrEmpty) || out.Len() != 0 {
		t.Fatalf("empty composition: %v %q", err, out.String())
	}
}

func TestKnown(t *testing.T) {
	if !Known(DNSLabels) || Known("passwords") {
		t.Fatal("Known")
	}
}

// SECURITY: a web list never carries a path or parameter that names a
// state-changing action: Normalize drops it for every web purpose, so both
// the build of a list and the composition of a task's list leave it out.
// Other purposes (DNS labels) keep such words.
func TestNormalizeDropsDestructiveEntries(t *testing.T) {
	for _, p := range []string{WebPaths, WebFiles, APIRoutes} {
		for _, in := range []string{"logout", "/admin/delete", "api/v1/users/deleteUser", "sign-out", "account/Log_Out",
			"reset-password", "index.php?action=remove", "%6cogout", "unsubscribe.html", "admin/shutdown"} {
			if e, ok := Normalize(p, in); ok {
				t.Errorf("%s: %q kept as %q", p, in, e)
			}
		}
		for _, in := range []string{"admin", "dropdown.js", "backup.zip", "api/v2/users", "killer-feature", "wiper.css"} {
			if _, ok := Normalize(p, in); !ok {
				t.Errorf("%s: %q dropped", p, in)
			}
		}
	}
	for _, in := range []string{"delete", "logout", "resetToken"} {
		if _, ok := Normalize(Params, in); ok {
			t.Errorf("params: %q kept", in)
		}
	}
	if _, ok := Normalize(DNSLabels, "delete"); !ok {
		t.Error("a dns label was dropped as destructive")
	}
	var out bytes.Buffer
	res, err := Compose(&out, Options{Purpose: WebPaths}, strings.NewReader("admin\nlogout\nbackup.zip\nusers/delete\n"))
	if err != nil || out.String() != "admin\nbackup.zip\n" || res.Invalid != 2 {
		t.Fatalf("composed %q (%+v, %v)", out.String(), res, err)
	}
}
