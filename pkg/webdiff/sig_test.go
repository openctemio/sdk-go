package webdiff

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestNormalizeRemovesDynamicContent(t *testing.T) {
	a := `<p>Not found: /x/k3j4h5g6f7d8 at 2026-11-05T10:00:00Z</p><input type="hidden" name="csrf" value="aaaa"><script nonce="abc123">x</script> id 0f1e2d3c4b5a69788796a5b4c3d2e1f0 req 123e4567-e89b-12d3-a456-426614174000 tok dGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZw==`
	b := `<p>Not found: /x/zz99yy88xx77 at 2027-01-01T23:59:59Z</p><input value="bbbb" type=hidden name="csrf"><script nonce='zzz'>x</script> id ffffffffffffffffffffffffffffffff req aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee tok YW5vdGhlciBsb25nIGJhc2U2NCBzdHJpbmcgaGVyZQ==`
	na, nb := Normalize(a, "k3j4h5g6f7d8"), Normalize(b, "ZZ99YY88XX77")
	if na != nb {
		t.Fatalf("normalised forms differ:\n%s\n%s", na, nb)
	}
	// The token is removed in its escaped forms too.
	if got := Normalize("go to %2Fa%20b and a&amp;b and a b", "a b"); strings.Contains(got, "a%20b") || strings.Contains(got, "a b") {
		t.Errorf("escaped token left: %q", got)
	}
}

func TestShapes(t *testing.T) {
	cases := map[string][3]string{
		"/admin":                {"/", "admin", ShapeBare},
		"/admin/":               {"/", "admin/", ShapeSlash},
		"/a/b/index.PHP":        {"/a/b/", "index.PHP", "ext:php"},
		"/a/.env":               {"/a/", ".env", ShapeDot},
		"/a/b.tar.gz":           {"/a/", "b.tar.gz", "ext:gz"},
		"/a/b~":                 {"/a/", "b~", ShapeBare},
		"/a/x.":                 {"/a/", "x.", ShapeBare},
		"/a/v1.2-beta":          {"/a/", "v1.2-beta", ShapeBare},
		"/a/b/c/":               {"/a/b/", "c/", ShapeSlash},
		"/index.php.bak":        {"/", "index.php.bak", "ext:bak"},
		"/x.verylongextension1": {"/", "x.verylongextension1", ShapeBare},
	}
	for in, want := range cases {
		d, n, s := Split(in)
		if [3]string{d, n, s} != want {
			t.Errorf("Split(%q) = %q %q %q, want %v", in, d, n, s, want)
		}
	}
}

func TestLocationPattern(t *testing.T) {
	req, _ := url.Parse("https://App.example.com/dir/abc123xyz789")
	cases := map[string]string{
		"/login?next=%2Fdir%2Fabc123xyz789":         "/login?next=%2Fdir%2F{r}",
		"https://app.example.com/dir/abc123xyz789/": "/dir/{r}/",
		"abc123xyz789/": "/dir/{r}/",
		"https://SSO.Example.com/auth?r=abc123xyz789#frag": "https://sso.example.com/auth?r={r}",
		"": "",
	}
	for loc, want := range cases {
		if got := LocationPattern(req, loc, "abc123xyz789"); got != want {
			t.Errorf("LocationPattern(%q) = %q, want %q", loc, got, want)
		}
	}
}

func TestFamily(t *testing.T) {
	for ct, want := range map[string]string{
		"text/html; charset=utf-8": "html", "application/json": "json", "application/problem+json": "json",
		"application/javascript": "js", "text/xml": "xml", "text/plain": "text", "application/zip": "binary",
		"": "none", "garbage;;": "binary",
	} {
		if got := Family(ct); got != want {
			t.Errorf("Family(%q) = %q, want %q", ct, got, want)
		}
	}
}

func TestSimHashSimilarity(t *testing.T) {
	a := strings.Repeat("the quick brown fox jumps over the lazy dog ", 20)
	b := a + " one more sentence at the end"
	c := strings.Repeat("completely different words make another page entirely here ", 20)
	if d := Distance(SimHash(a), SimHash(b)); d > 10 {
		t.Errorf("similar texts %d bits apart", d)
	}
	if d := Distance(SimHash(a), SimHash(c)); d < 10 {
		t.Errorf("different texts only %d bits apart", d)
	}
}

func FuzzNormalize(f *testing.F) {
	for _, s := range []string{"", "<title>x</title>", "nonce='a' 123 0xdeadbeefdeadbeef", `<input type=hidden value=1>`} {
		f.Add(s, "token")
	}
	f.Fuzz(func(t *testing.T, body, tok string) {
		out := Normalize(body, tok)
		if len(out) > len(body) {
			t.Fatalf("normalised form longer than the body: %d > %d", len(out), len(body))
		}
		if Normalize(body, tok) != out {
			t.Fatal("not deterministic")
		}
	})
}

func FuzzSimHash(f *testing.F) {
	f.Add("a b c d e")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		a, b := SimHash(s), SimHash(s)
		if a != b || Distance(a, b) != 0 {
			t.Fatal("not deterministic")
		}
		if strings.TrimSpace(s) == "" && SimHash(s) != 0 {
			t.Fatal("an empty text has a hash")
		}
	})
}

func FuzzLocationPattern(f *testing.F) {
	f.Add("/login?next=%2Fx", "x1y2z3")
	f.Add("http://[::1", "abc")
	f.Add("//evil.example/%zz", "abc")
	req, _ := url.Parse("https://app.example.com/d/x1y2z3")
	f.Fuzz(func(t *testing.T, loc, tok string) {
		out := LocationPattern(req, loc, tok)
		if len(out) > 512 {
			t.Fatalf("pattern of %d bytes", len(out))
		}
		if loc == "" && out != "" {
			t.Fatal("a pattern without a Location")
		}
		if strings.ContainsAny(out, "\r\n") && !strings.ContainsAny(loc, "\r\n") {
			t.Fatalf("pattern %q gained a line break", out)
		}
	})
}

// The endpoint of a hit carries the evidence and nothing of the body.
func TestEndpointOfAHit(t *testing.T) {
	h := &Hit{Path: "/backup.zip", Status: 200, ContentType: "application/zip", Size: 1234, Hash: "0123456789abcdef", Auth: AuthNone, Labels: []string{LabelForbidden}}
	e := Endpoint("https://app.example.com", h)
	if e.Method != "GET" || e.Path != "/backup.zip" || e.StatusCode != 200 || e.Source != "probe" || e.Auth != "none" || e.Kind != "other" {
		t.Fatalf("%+v", e)
	}
	b, _ := json.Marshal(e)
	want := `"io.openctem":{"labels":["status:forbidden"],"response":{"hash":"0123456789abcdef","size":1234}}`
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s lacks %s", b, want)
	}
}
