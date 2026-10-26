package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResponseHeadersFromAllowList(t *testing.T) {
	in := map[string][]string{
		"strict-transport-security":        {"max-age=63072000; includeSubDomains"},
		"Content-Security-Policy":          {"default-src 'self'"},
		"X-FRAME-OPTIONS":                  {"DENY"},
		"X-Content-Type-Options":           {"nosniff"},
		"Referrer-Policy":                  {"no-referrer"},
		"Permissions-Policy":               {"camera=()"},
		"Access-Control-Allow-Origin":      {"*"},
		"Access-Control-Allow-Credentials": {"true"},
		"Server":                           {"nginx/1.25"},
		"X-Api-Key":                        {"sk_live_SECRETSECRET"},
		"Authorization":                    {"Bearer SECRETSECRET"},
		"Location":                         {"https://x/?token=SECRETSECRET"},
		"Set-Cookie": {
			"sid=SECRETVALUE123; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Lax",
			"pref=SECRETVALUE456; Max-Age=3600",
		},
	}
	got := ResponseHeadersFrom(in)
	if got == nil {
		t.Fatal("nil")
	}
	if len(got.Values) != 8 {
		t.Fatalf("want 8 allow-listed values, got %v", got.Values)
	}
	for _, name := range AllowedResponseHeaders() {
		if got.Values[name] == "" {
			t.Errorf("%s missing", name)
		}
	}
	if len(got.Cookies) != 2 {
		t.Fatalf("cookies: %+v", got.Cookies)
	}
	// Sorted by name: pref, sid.
	if c := got.Cookies[1]; c.Name != "sid" || !c.Secure || !c.HTTPOnly || c.SameSite != "lax" || c.Persistent {
		t.Errorf("sid flags: %+v", c)
	}
	if c := got.Cookies[0]; c.Name != "pref" || c.Secure || !c.Persistent {
		t.Errorf("pref flags: %+v", c)
	}
	b, _ := json.Marshal(got)
	for _, leak := range []string{"SECRET", "nginx", "example.com", "Authorization", "Server", "Location"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("%q reached the output: %s", leak, b)
		}
	}
}

func TestResponseHeadersFromHostileValues(t *testing.T) {
	big := strings.Repeat("a", MaxHeaderValueBytes+1)
	cases := map[string][]string{
		"crlf":     {"max-age=1\r\nSet-Cookie: x=y"},
		"nul":      {"max-age=1\x00"},
		"bell":     {"max-age=1\x07"},
		"del":      {"max-age=1\x7f"},
		"bidi":     {"max-age=1\u202e"},
		"badutf8":  {"max-age=\xff\xfe"},
		"1MiB":     {strings.Repeat("a", 1<<20)},
		"overcap":  {big},
		"empty":    {"  "},
		"emptyset": nil,
	}
	for name, v := range cases {
		if got := ResponseHeadersFrom(map[string][]string{"Strict-Transport-Security": v}); got != nil {
			t.Errorf("%s: value passed: %+v", name, got)
		}
	}
	// Exactly at the cap passes.
	ok := strings.Repeat("a", MaxHeaderValueBytes)
	if got := ResponseHeadersFrom(map[string][]string{"Content-Security-Policy": {ok}}); got == nil {
		t.Error("value at the cap dropped")
	}
	// Multiple lines join.
	got := ResponseHeadersFrom(map[string][]string{"Content-Security-Policy": {"a", "b"}})
	if got.Values["Content-Security-Policy"] != "a, b" {
		t.Errorf("join: %v", got.Values)
	}
}

func TestCookieFlagsFrom(t *testing.T) {
	good := map[string]CookieFlags{
		"a=b":                                   {Name: "a"},
		"__Host-id=1; Secure; Path=/":           {Name: "__Host-id", Secure: true},
		"x=; HTTPONLY; samesite=STRICT":         {Name: "x", HTTPOnly: true, SameSite: "strict"},
		"x=1; SameSite=Unknown; expires=Sun, 1": {Name: "x", Persistent: true},
	}
	for line, want := range good {
		got, ok := CookieFlagsFrom(line)
		if !ok || got != want {
			t.Errorf("%q: %+v %v, want %+v", line, got, ok, want)
		}
	}
	for _, line := range []string{
		"", "novalue", "=v", "a b=c", "a;b=c", "a\r\n=b", "a\x00=b", "a=b\r\nX: y",
		strings.Repeat("n", 129) + "=v", "n=" + strings.Repeat("v", 1<<20), "é=v",
	} {
		if got, ok := CookieFlagsFrom(line); ok {
			t.Errorf("%.40q accepted: %+v", line, got)
		}
	}
}

func TestResponseHeadersCookieCap(t *testing.T) {
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, "c"+strings.Repeat("x", i)+"=v")
	}
	got := ResponseHeadersFrom(map[string][]string{"Set-Cookie": lines})
	if len(got.Cookies) != MaxCookies {
		t.Errorf("cookies %d", len(got.Cookies))
	}
}

func TestBoundRevalidatesDecodedJSON(t *testing.T) {
	raw := `{"values":{"Server":"nginx","strict-transport-security":"max-age=1","X-Frame-Options":"a\r\nb"},
		"cookies":[{"name":"ok","secure":true,"same_site":"LAX"},{"name":"bad name"},{"name":"v=1"}]}`
	var r ResponseHeaders
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	b := r.Bound()
	if len(b.Values) != 1 || b.Values["Strict-Transport-Security"] != "max-age=1" {
		t.Errorf("values %v", b.Values)
	}
	if len(b.Cookies) != 1 || b.Cookies[0].Name != "ok" || b.Cookies[0].SameSite != "lax" {
		t.Errorf("cookies %+v", b.Cookies)
	}
	if (*ResponseHeaders)(nil).Bound() != nil {
		t.Error("nil")
	}
}

func TestSanitizeCNAMEs(t *testing.T) {
	got := SanitizeCNAMEs([]string{"Foo.Example.COM.", "bad host", "x\r\ny.com", "", "a..b", ".lead", "javascript:alert(1)", strings.Repeat("a", 254), "ok-1.cdn.net"})
	if strings.Join(got, ",") != "foo.example.com,ok-1.cdn.net" {
		t.Errorf("%v", got)
	}
	var many []string
	for i := 0; i < 20; i++ {
		many = append(many, "h.example.com")
	}
	if n := len(SanitizeCNAMEs(many)); n != MaxCNAMEs {
		t.Errorf("cap %d", n)
	}
}

func TestSanitizeURLParams(t *testing.T) {
	in := []URLParam{
		{"form", "user"}, {"FORM", " user "}, {"query", "q"}, {"nowhere", "x"},
		{"form", ""}, {"form", "a\r\nb"}, {"form", "n\x00"}, {"form", strings.Repeat("a", 129)},
		{"form", strings.Repeat("a", 1<<20)},
	}
	got := SanitizeURLParams(in)
	if len(got) != 2 || got[0] != (URLParam{"form", "user"}) || got[1] != (URLParam{"query", "q"}) {
		t.Errorf("%+v", got)
	}
	var many []URLParam
	for i := 0; i < 300; i++ {
		many = append(many, URLParam{"form", "p" + strings.Repeat("x", i%100) + string(rune('a'+i%26)) + strings.Repeat("y", i/100)})
	}
	if n := len(SanitizeURLParams(many)); n > MaxURLParams {
		t.Errorf("cap %d", n)
	}
}

func TestDiscoveredURLSanitize(t *testing.T) {
	good := DiscoveredURL{
		URL:         "https://u:p@example.com/a/b?token=SECRET&id=7#frag",
		Method:      "post",
		Source:      "form",
		Parent:      "https://example.com/login?next=/admin&sid=SECRET#x",
		ContentType: "Text/HTML; charset=UTF-8",
		Params:      []URLParam{{"form", "username"}, {"form", "password"}},
		Forms: []WebForm{{
			Method: "post", Action: "https://example.com/login?csrf=SECRET",
			Params: []URLParam{{"query", "will-be-form"}, {"form", "password"}}, PasswordField: true,
		}},
	}
	got, ok := good.Sanitize()
	if !ok {
		t.Fatal("dropped")
	}
	if got.URL != "https://example.com/a/b?token=&id=" || got.Method != "POST" {
		t.Errorf("url %q method %q", got.URL, got.Method)
	}
	if got.Parent != "https://example.com/login?next=&sid=" {
		t.Errorf("parent %q", got.Parent)
	}
	if got.ContentType != "text/html" {
		t.Errorf("content type %q", got.ContentType)
	}
	if len(got.Params) != 2 {
		t.Errorf("params %+v", got.Params)
	}
	f := got.Forms[0]
	if f.Method != "POST" || f.Action != "https://example.com/login" || !f.PasswordField || len(f.Params) != 2 || f.Params[0].Location != ParamLocationForm {
		t.Errorf("form %+v", f)
	}
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "SECRET") || strings.Contains(string(b), "u:p") || strings.Contains(string(b), "frag") {
		t.Errorf("value leaked: %s", b)
	}
}

func TestDiscoveredURLSanitizeHostile(t *testing.T) {
	for name, u := range map[string]string{
		"javascript": "javascript:alert(1)",
		"data":       "data:text/html,<script>",
		"file":       "file:///etc/passwd",
		"crlf":       "https://example.com/a\r\nX: y",
		"nul":        "https://example.com/a\x00",
		"space":      "https://example.com/a b",
		"1MiB":       "https://example.com/" + strings.Repeat("a", 1<<20),
		"nohost":     "https:///path",
		"empty":      "",
		"badutf8":    "https://example.com/\xff",
	} {
		if _, ok := (DiscoveredURL{URL: u}).Sanitize(); ok {
			t.Errorf("%s accepted", name)
		}
	}
	for _, m := range []string{"GET\r\nX", "G E T", "VERYLONGMETHODNAME", "\x00"} {
		if _, ok := (DiscoveredURL{URL: "https://example.com/", Method: m}).Sanitize(); ok {
			t.Errorf("method %q accepted", m)
		}
	}
	got, ok := DiscoveredURL{
		URL: "https://example.com/", Parent: "javascript:alert(1)", ContentType: "text/html\r\nX: y",
		Source: strings.Repeat("s", 65), Type: "form\x00", Extension: ".php",
		Forms: []WebForm{{Action: "javascript:alert(1)", Method: "TRACE"}},
	}.Sanitize()
	if !ok {
		t.Fatal("dropped")
	}
	if got.Parent != "" || got.ContentType != "" || got.Source != "" || got.Type != "" || got.Extension != ".php" {
		t.Errorf("%+v", got)
	}
	if f := got.Forms[0]; f.Action != "" || f.Method != "GET" {
		t.Errorf("form %+v", f)
	}
	var forms []WebForm
	for i := 0; i < 50; i++ {
		forms = append(forms, WebForm{})
	}
	if n := len(SanitizeForms(forms)); n != MaxURLForms {
		t.Errorf("forms cap %d", n)
	}
}

func TestMediaType(t *testing.T) {
	for in, want := range map[string]string{
		"application/json":              "application/json",
		"APPLICATION/JSON;charset=utf":  "application/json",
		"text/html; boundary=\r\n":      "text/html",
		"nosubtype":                     "",
		"a/b/c":                         "",
		"a b/c":                         "",
		"":                              "",
		strings.Repeat("a", 300) + "/b": "",
		"te\x00xt/html":                 "",
	} {
		if got := mediaType(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
}

func TestNewFieldsRoundTrip(t *testing.T) {
	h := LiveHost{URL: "https://a/", ResponseHeaders: ResponseHeadersFrom(map[string][]string{"Referrer-Policy": {"no-referrer"}}), CNAMEs: []string{"x.cdn.net"}}
	b, _ := json.Marshal(h)
	var back LiveHost
	if err := json.Unmarshal(b, &back); err != nil || back.ResponseHeaders.Values["Referrer-Policy"] != "no-referrer" || back.CNAMEs[0] != "x.cdn.net" {
		t.Errorf("%s %v", b, err)
	}
	// Old payloads without the new members still decode.
	if err := json.Unmarshal([]byte(`{"url":"https://a/"}`), &back); err != nil {
		t.Error(err)
	}
}

func TestNewWebFormPasswordFlag(t *testing.T) {
	for _, n := range []string{"password", "Password", "user_passwd", "pwd", "txtPWD", "pass", "passcode", "passphrase", "new-password"} {
		if !NewWebForm("POST", "", []string{"user", n}).PasswordField {
			t.Errorf("%q not a password field", n)
		}
	}
	for _, n := range []string{"user", "email", "compas", "token", "", "pas"} {
		if NewWebForm("POST", "", []string{n}).PasswordField {
			t.Errorf("%q flagged", n)
		}
	}
	f := NewWebForm("post", "/x", []string{"a", "b"})
	if len(f.Params) != 2 || f.Params[0].Location != ParamLocationForm {
		t.Errorf("%+v", f)
	}
}
