package tool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

type probeConfig struct {
	Ruleset string   `json:"ruleset" enum:"default,strict" default:"default" description:"Rule set"`
	Depth   int      `json:"depth" min:"1" max:"10" default:"3"`
	Tags    []string `json:"tags" maxItems:"8" default:"a,b"`
	Fast    bool     `json:"fast" scope:"scan"`
	Limits  struct {
		RPS int `json:"rps" min:"1" max:"1000" default:"50"`
	} `json:"limits"`
}

var probeManifest = Manifest{
	Name: "probe", Version: "1.0.0", Class: TargetScan, Tier: T1,
	Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
}

func TestSchemaForIsDeterministicAndValid(t *testing.T) {
	a, err := SchemaFor[probeConfig]()
	if err != nil {
		t.Fatal(err)
	}
	for range 20 {
		b, _ := SchemaFor[probeConfig]()
		if !bytes.Equal(a, b) {
			t.Fatal("schema export is not deterministic")
		}
	}
	m := probeManifest
	m.Config = a
	if err := m.Validate(); err != nil {
		t.Fatalf("derived schema refused: %v\n%s", err, a)
	}
	if s, _ := m.ConfigSchema(); s.Property("limits.rps") == nil || s.Property("fast").Scope != "scan" {
		t.Fatalf("derived schema %s", a)
	}
	if raw, err := SchemaFor[NoConfig](); err != nil || raw != nil {
		t.Fatalf("NoConfig: %s %v", raw, err)
	}
}

func TestSchemaForRefusesSecrets(t *testing.T) {
	type withSecret struct {
		Token string `json:"token" secret:"true"`
	}
	if _, err := SchemaFor[withSecret](); err == nil || !strings.Contains(err.Error(), "credential") {
		t.Fatalf("got %v", err)
	}
	type untagged struct{ Rate int }
	if _, err := SchemaFor[untagged](); err == nil {
		t.Fatal("a field without a json tag must be refused")
	}
	type nested struct {
		A struct {
			B struct {
				C int `json:"c"`
			} `json:"b"`
		} `json:"a"`
	}
	if _, err := SchemaFor[nested](); err == nil {
		t.Fatal("two levels of groups must be refused")
	}
	// New panics on a manifest it would refuse.
	defer func() {
		if recover() == nil {
			t.Fatal("New must panic on an invalid manifest")
		}
	}()
	bad := probeManifest
	bad.Tier = "T9"
	New(bad, func(Context, Task, NoConfig) error { return nil })
}

func TestNewDecodesConfigWithDefaults(t *testing.T) {
	var got probeConfig
	tl := New(probeManifest, func(_ Context, _ Task, cfg probeConfig) error {
		got = cfg
		return nil
	})
	if len(tl.Manifest().Config) == 0 {
		t.Fatal("config schema not derived")
	}
	if err := tl.Run(nil, Task{Config: json.RawMessage(`{"depth":5,"limits":{}}`)}); err != nil {
		t.Fatal(err)
	}
	if got.Depth != 5 || got.Ruleset != "default" || got.Limits.RPS != 50 || len(got.Tags) != 2 {
		t.Fatalf("decoded %+v", got)
	}
	for _, bad := range []string{`{"depth":99}`, `{"unknown":1}`, `{"ruleset":"loose"}`, `[1]`} {
		err := tl.Run(nil, Task{Config: json.RawMessage(bad)})
		if ClassOf(err) != InvalidInput {
			t.Errorf("%s: %v", bad, err)
		}
	}
	none := New(probeManifest, func(Context, Task, NoConfig) error { return nil })
	if err := none.Run(nil, Task{Config: json.RawMessage(`{"x":1}`)}); ClassOf(err) != InvalidInput {
		t.Fatalf("config given to a tool without config: %v", err)
	}
}

func TestErrorClasses(t *testing.T) {
	cases := []struct {
		err       error
		class     ErrorClass
		retryable bool
	}{
		{Unreachable(errors.New("dial")), TargetUnreachable, true},
		{Retry(errors.New("503")), Transient, true},
		{RateLimit(time.Minute, nil), RateLimited, true},
		{Refused("scope"), RefusedByPolicy, false},
		{Invalid("bad %s", "x"), InvalidInput, false},
		{AuthFailure(errors.New("401")), AuthFailed, false},
		{Failed(errors.New("boom")), ToolError, false},
		{errors.New("plain"), ToolError, false},
		{fmt.Errorf("wrapped: %w", Unreachable(nil)), TargetUnreachable, true},
		{context.Canceled, Canceled, false},
		{context.DeadlineExceeded, Timeout, true},
		// A tool cannot claim a runtime-only class.
		{&Error{Class: ToolCrashed, Retryable: true}, ToolError, false},
		{&Error{Class: "made_up"}, ToolError, false},
	}
	for _, c := range cases {
		e := AsError(c.err)
		if e.Class != c.class || e.Retryable != c.retryable {
			t.Errorf("%v: class %s retryable %t, want %s %t", c.err, e.Class, e.Retryable, c.class, c.retryable)
		}
	}
	if AsError(nil) != nil || ClassOf(nil) != "" {
		t.Error("nil")
	}
	if e := AsError(RateLimit(time.Minute, nil)); e.RetryAfter != time.Minute {
		t.Error("retry after lost")
	}
	long := strings.Repeat("é", 300)
	if c := CapDetail(long); len(c) > MaxErrorDetail || !strings.HasPrefix(long, c) {
		t.Errorf("CapDetail: %d bytes", len(c))
	}
}

func TestSecretNeverPrints(t *testing.T) {
	s := NewSecret("hunter2-very-secret")
	type holder struct {
		Key Secret `json:"key"`
	}
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	log.Info("x", "secret", s, "holder", holder{s})
	js, _ := json.Marshal(holder{s})
	txt, _ := s.MarshalText()
	outs := []string{
		fmt.Sprint(s), fmt.Sprintf("%v %+v %#v %s %q %x", s, s, s, s, s, s),
		fmt.Sprintf("%+v %#v", holder{s}, holder{s}), string(js), string(txt), buf.String(), s.String(), s.GoString(),
	}
	for _, o := range outs {
		if strings.Contains(o, "hunter2") {
			t.Fatalf("secret leaked: %s", o)
		}
	}
	if s.Reveal() != "hunter2-very-secret" || s.IsZero() || !NewSecret("").IsZero() {
		t.Fatal("Reveal/IsZero")
	}
}

func TestTargetHelpers(t *testing.T) {
	cases := []struct {
		t          Target
		url, host  string
		port       int
		urlPath    string
		urlWithout string
	}{
		{Target{Value: "https://a.example:8443/app"}, "https://a.example:8443/app/.env", "a.example", 8443, ".env", ""},
		{Target{Value: "http://a.example"}, "http://a.example/x", "a.example", 80, "x", ""},
		{Target{Value: "a.example"}, "https://a.example/x", "a.example", 0, "x", ""},
		{Target{Value: "10.0.4.7:22", Attrs: map[string]string{"port": "2222"}}, "https://10.0.4.7:22/x", "10.0.4.7", 22, "x", ""},
		{Target{Value: "10.0.4.7", Attrs: map[string]string{"port": "2222"}}, "https://10.0.4.7/x", "10.0.4.7", 2222, "x", ""},
		{Target{Value: "/src/repo"}, "", "", 0, "x", ""},
	}
	for _, c := range cases {
		if got := c.t.URL(c.urlPath); got != c.url {
			t.Errorf("%s URL: %q want %q", c.t.Value, got, c.url)
		}
		if got := c.t.Host(); got != c.host {
			t.Errorf("%s Host: %q want %q", c.t.Value, got, c.host)
		}
		if got := c.t.Port(); got != c.port {
			t.Errorf("%s Port: %d want %d", c.t.Value, got, c.port)
		}
	}
}
