package scopelimit

import (
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	hosts := []string{"https://api.example.com/v1", "api.example.com:8443", "10.0.0.5", "App.Example.com."}
	good := [][]Limit{
		{{Host: "api.example.com", Ports: "443,8000-8100", Protocol: "tcp", PathPrefix: "/v1"}},
		{{Host: "10.0.0.5", Ports: "22"}},
		{{Host: "app.example.com", PathPrefix: "/"}},
	}
	for i, ls := range good {
		if err := Validate(ls, hosts); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}
	bad := map[string]Limit{
		"not a target":       {Host: "other.example.com", Ports: "443"},
		"upper case host":    {Host: "API.example.com", Ports: "443"},
		"wildcard host":      {Host: "*.example.com", Ports: "443"},
		"empty limit":        {Host: "api.example.com"},
		"port 0":             {Host: "api.example.com", Ports: "0"},
		"port 65536":         {Host: "api.example.com", Ports: "65536"},
		"not canonical":      {Host: "api.example.com", Ports: "443,80"},
		"overlap":            {Host: "api.example.com", Ports: "80-90,85"},
		"adjacent":           {Host: "api.example.com", Ports: "80,81"},
		"leading zero":       {Host: "api.example.com", Ports: "0443"},
		"spaces":             {Host: "api.example.com", Ports: "443, 80"},
		"reverse range":      {Host: "api.example.com", Ports: "90-80"},
		"protocol":           {Host: "api.example.com", Protocol: "sctp"},
		"udp path":           {Host: "api.example.com", Protocol: "udp", PathPrefix: "/a"},
		"relative path":      {Host: "api.example.com", PathPrefix: "api"},
		"dot segment":        {Host: "api.example.com", PathPrefix: "/api/../admin"},
		"encoded dot":        {Host: "api.example.com", PathPrefix: "/api/%2e%2e/admin"},
		"encoded slash":      {Host: "api.example.com", PathPrefix: "/api%2fadmin"},
		"query":              {Host: "api.example.com", PathPrefix: "/api?x=1"},
		"double slash":       {Host: "api.example.com", PathPrefix: "/a//b"},
		"control in path":    {Host: "api.example.com", PathPrefix: "/a\x00b"},
		"backslash":          {Host: "api.example.com", PathPrefix: `/a\b`},
		"dot with parameter": {Host: "api.example.com", PathPrefix: "/a/..;/b"},
	}
	for name, l := range bad {
		if err := Validate([]Limit{l}, hosts); err == nil {
			t.Errorf("%s: accepted %+v", name, l)
		}
	}
}

func TestSetPorts(t *testing.T) {
	s := NewSet([]Limit{
		{Host: "api.example.com", Ports: "443"},
		{Host: "api.example.com", Ports: "8000-8100", Protocol: "tcp"},
		{Host: "10.0.0.5", Ports: "53", Protocol: "udp"},
	})
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"api.example.com", 443, true},
		{"API.Example.com.", 8050, true},
		{"api.example.com", 8101, false},
		{"api.example.com", 22, false},
		{"10.0.0.5", 53, false}, // udp only; the forwarder is tcp
		{"::ffff:10.0.0.5", 53, false},
		{"free.example.com", 22, true},
	}
	for _, c := range cases {
		if got := s.AllowsPort(c.host, c.port); got != c.want {
			t.Errorf("AllowsPort(%s, %d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
	if got := s.PortList("api.example.com"); got != "443,8000-8100" {
		t.Errorf("PortList = %q", got)
	}
}

func TestPathPrefixes(t *testing.T) {
	s := NewSet([]Limit{
		{Host: "a.example.com", Ports: "443", PathPrefix: "/api"},
		{Host: "a.example.com", Ports: "443", PathPrefix: "/v2/"},
		{Host: "a.example.com", Ports: "8443"},
	})
	if pre, guarded := s.PathPrefixes("a.example.com", 443); !guarded || len(pre) != 2 {
		t.Fatalf("443: %v %v", pre, guarded)
	}
	if _, guarded := s.PathPrefixes("a.example.com", 8443); guarded {
		t.Fatal("8443 allows every path")
	}
	if _, guarded := s.PathPrefixes("b.example.com", 443); guarded {
		t.Fatal("an unlimited host is not guarded")
	}
}

func TestPathAllowed(t *testing.T) {
	prefixes := []string{"/api", "/v2/"}
	allowed := []string{"/api", "/api/", "/api/users", "/api/a/../b", "/v2", "/v2/x", "/api/%41", "/api/x;y=1",
		"/api/caf%C3%A9", "/./api/x"}
	refused := []string{
		"/", "/apiadmin", "/admin", "/API/users", "/Api", // case sensitive, segment boundary
		"/api/../admin", "/api/%2e%2e/admin", "/api/%2E%2E/admin", "/api/..%2fadmin", "/api%2f..%2fadmin",
		"/api/..;/admin", "/api/.;/../../admin", "/api%5c..%5cadmin", `/api\..\admin`, "/api/%00",
		"/api/%zz", "api/x", "/v2x", "/api/%0d%0aHost:x",
	}
	for _, p := range allowed {
		if err := PathAllowed(p, prefixes); err != nil {
			t.Errorf("%q refused: %v", p, err)
		}
	}
	for _, p := range refused {
		err := PathAllowed(p, prefixes)
		if err == nil {
			t.Errorf("%q allowed", p)
			continue
		}
		if !errors.Is(err, ErrOutside) {
			t.Errorf("%q: error %v is not ErrOutside", p, err)
		}
	}
	if err := PathAllowed("/anything", []string{"/"}); err != nil {
		t.Errorf("root prefix: %v", err)
	}
	if err := PathAllowed("/api", nil); err == nil {
		t.Error("no prefix allows nothing")
	}
}

func TestHostOf(t *testing.T) {
	for in, want := range map[string]string{
		"https://API.example.com:8443/x": "api.example.com", "api.example.com:8443": "api.example.com",
		"api.example.com": "api.example.com", "10.0.0.5": "10.0.0.5", "[2001:db8::1]:443": "2001:db8::1",
		"10.0.0.0/24": "", "/src": "", "": "",
	} {
		if got := HostOf(in); got != want {
			t.Errorf("HostOf(%q) = %q, want %q", in, got, want)
		}
	}
}
