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
