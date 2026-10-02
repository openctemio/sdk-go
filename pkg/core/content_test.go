package core

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestToolInfoContentJSON(t *testing.T) {
	up := time.Date(2026, 10, 2, 1, 5, 41, 0, time.UTC)
	ti := ToolInfo{Name: "trivy", Version: "0.69.3", Installed: true, Content: []ContentInfo{{
		Name: ContentTrivyDB, Version: "2026-10-02T01:05:41Z", UpdatedAt: &up,
		Source: "mirror.gcr.io/aquasec/trivy-db:2", Digest: "sha256:abc", Managed: true,
	}}}
	raw, err := json.Marshal(ti)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"name":"trivy","version":"0.69.3","installed":true,"content":[{"name":"trivy-db","version":"2026-10-02T01:05:41Z","updated_at":"2026-10-02T01:05:41Z","source":"mirror.gcr.io/aquasec/trivy-db:2","digest":"sha256:abc","managed":true}]}`
	if string(raw) != want {
		t.Fatalf("got  %s\nwant %s", raw, want)
	}

	// No content: the member is absent (a platform from before content
	// sees the same tool entry as before).
	raw, _ = json.Marshal(ToolInfo{Name: "semgrep", Installed: true})
	if strings.Contains(string(raw), "content") {
		t.Fatalf("content member without content: %s", raw)
	}
}

func TestCapabilityReportApplyCopiesContent(t *testing.T) {
	content := []ContentInfo{{Name: ContentNucleiTemplates, Version: "v10.4.9", Managed: true}}
	r := CapabilityReport{Tools: []ToolInfo{{Name: "nuclei", Installed: true, Content: content}}}
	st := &SensorStatus{}
	r.Apply(st)
	content[0].Version = "changed"
	if got := st.Tools[0].Content[0].Version; got != "v10.4.9" {
		t.Fatalf("Apply aliased the content slice: %q", got)
	}
}

func TestContentInfoAge(t *testing.T) {
	now := time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)
	up := now.Add(-72 * time.Hour)
	fetched := now.Add(-time.Hour)
	if age, ok := (ContentInfo{UpdatedAt: &up, FetchedAt: &fetched}).Age(now); !ok || age != 72*time.Hour {
		t.Fatalf("age from updated_at: %v %v", age, ok)
	}
	if age, ok := (ContentInfo{FetchedAt: &fetched}).Age(now); !ok || age != time.Hour {
		t.Fatalf("age from fetched_at: %v %v", age, ok)
	}
	if _, ok := (ContentInfo{}).Age(now); ok {
		t.Fatal("age without timestamps")
	}
}

func TestParseRefreshContentRequest(t *testing.T) {
	for _, empty := range []string{"", "null", "{}", "  "} {
		req, err := ParseRefreshContentRequest(json.RawMessage(empty))
		if err != nil || req == nil || req.Force || len(req.Content) != 0 || req.Policy != nil {
			t.Fatalf("%q: %+v %v", empty, req, err)
		}
	}

	req, err := ParseRefreshContentRequest(json.RawMessage(`{
		"content": ["trivy-db", "nuclei-templates"], "force": true,
		"policy": {"refresh_interval_hours": 12, "content": {
			"trivy-db": {"max_age_hours": 48, "version": "sha256:3b16"},
			"semgrep-rules": {"rulesets": ["p/default", "p/owasp-top-ten"]}
		}},
		"unknown_member": 1
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if !req.Force || len(req.Content) != 2 || req.Policy.RefreshIntervalHours != 12 {
		t.Fatalf("decoded %+v", req)
	}
	if pin := req.Policy.Content[ContentTrivyDB]; pin.MaxAge() != 48*time.Hour || pin.Version != "sha256:3b16" {
		t.Fatalf("trivy pin %+v", pin)
	}
	if got := req.Policy.Content[ContentSemgrepRules].Rulesets; len(got) != 2 {
		t.Fatalf("rulesets %v", got)
	}
	if (ContentPin{}).MaxAge() != 0 {
		t.Fatal("unset max age")
	}

	bad := []string{
		`{"content": ["Trivy DB"]}`,
		`{"content": ["../x"]}`,
		`{"policy": {"refresh_interval_hours": -1}}`,
		`{"policy": {"content": {"trivy-db": {"max_age_hours": 9999999}}}}`,
		`{"policy": {"content": {"trivy-db": {"version": "--db-repository=evil"}}}}`,
		`{"policy": {"content": {"trivy-db": {"version": "a b"}}}}`,
		`{"policy": {"content": {"semgrep-rules": {"rulesets": [""]}}}}`,
		`{"policy": {"content": {"semgrep-rules": {"rulesets": ["-c"]}}}}`,
		`{"policy": {"content": {"BAD": {}}}}`,
		`{"content": "trivy-db"}`,
		`not json`,
	}
	for _, b := range bad {
		if _, err := ParseRefreshContentRequest(json.RawMessage(b)); !errors.Is(err, ErrInvalidRefreshContent) {
			t.Errorf("%s: want ErrInvalidRefreshContent, got %v", b, err)
		}
	}
}

func TestContentInfoStale(t *testing.T) {
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	at := func(d time.Duration) *time.Time { v := now.Add(-d); return &v }
	maxAge := 14 * 24 * time.Hour
	cases := []struct {
		name string
		c    ContentInfo
		max  time.Duration
		want bool
	}{
		{"fresh", ContentInfo{UpdatedAt: at(24 * time.Hour)}, maxAge, false},
		{"old, never confirmed", ContentInfo{UpdatedAt: at(20 * 24 * time.Hour)}, maxAge, true},
		{"old, newest release confirmed an hour ago", ContentInfo{UpdatedAt: at(20 * 24 * time.Hour), CheckedAt: at(time.Hour)}, maxAge, false},
		{"old, last confirmed long ago (refresh failing)", ContentInfo{UpdatedAt: at(20 * 24 * time.Hour), CheckedAt: at(15 * 24 * time.Hour)}, maxAge, true},
		{"no limit", ContentInfo{UpdatedAt: at(400 * 24 * time.Hour)}, 0, false},
		{"unknown age", ContentInfo{}, maxAge, false},
	}
	for _, tc := range cases {
		if got := tc.c.Stale(now, tc.max); got != tc.want {
			t.Errorf("%s: Stale = %v, want %v", tc.name, got, tc.want)
		}
	}
}
