package toolrt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var testManifest = tool.Manifest{
	Name: "probe", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"http_service"},
	Produces: []string{"asset:domain", "finding:misconfiguration"},
}

func finding(title string) ctis.Finding {
	return ctis.Finding{Type: "misconfiguration", Title: title, Severity: "high"}
}

func TestCheckerRefusesUndeclaredOutput(t *testing.T) {
	c := NewChecker(testManifest.Normalized())
	if _, err := c.Asset(ctis.Asset{Type: "ip_address", Value: "10.0.0.1"}); !errors.Is(err, tool.ErrUndeclaredOutput) {
		t.Fatalf("undeclared asset: %v", err)
	}
	if _, err := c.Finding(ctis.Finding{Type: "secret", Title: "x", Severity: "high"}); !errors.Is(err, tool.ErrUndeclaredOutput) {
		t.Fatalf("undeclared finding: %v", err)
	}
	if _, err := c.Dependency(ctis.Dependency{Name: "lib"}); !errors.Is(err, tool.ErrUndeclaredOutput) {
		t.Fatalf("undeclared dependency: %v", err)
	}
	st := c.Stats()
	if st.Records != 0 || st.Quarantined["asset:ip_address"] != 1 || st.Quarantined["finding:secret"] != 1 || st.Quarantined["dependency"] != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestCheckerCapsRecordsAndBytes(t *testing.T) {
	m := testManifest
	m.Resources.MaxRecords = 3
	c := NewChecker(m.Normalized())
	for i := range 3 {
		if _, err := c.Finding(finding("f")); err != nil {
			t.Fatalf("%d: %v", i, err)
		}
	}
	if _, err := c.Finding(finding("f")); !errors.Is(err, tool.ErrOutputLimit) {
		t.Fatalf("4th record: %v", err)
	}
	m = testManifest
	m.Resources.MaxOutputBytes = 300
	c = NewChecker(m.Normalized())
	if _, err := c.Finding(finding(strings.Repeat("x", 400))); !errors.Is(err, tool.ErrOutputLimit) {
		t.Fatalf("byte cap: %v", err)
	}
	if !c.Stats().Capped {
		t.Fatal("capped not recorded")
	}
}

func TestCheckerSanitizes(t *testing.T) {
	c := NewChecker(testManifest.Normalized())
	evil := "admin\u202e\u2066gpj.exe\x1b[31m\x00ok\tline\nnext"
	f, err := c.Finding(ctis.Finding{Type: "misconfiguration", Title: evil, Severity: "high", Description: "bad utf8 \xff\xfe end"})
	if err != nil {
		t.Fatal(err)
	}
	if f.Title != "admingpj.exe[31mok\tline\nnext" {
		t.Fatalf("title %q", f.Title)
	}
	if !strings.Contains(f.Description, "�") || strings.Contains(f.Description, "\xff") {
		t.Fatalf("description %q", f.Description)
	}
	long := strings.Repeat("a", MaxString+100)
	f, err = c.Finding(ctis.Finding{Type: "misconfiguration", Title: "t", Severity: "high", Description: long})
	if err != nil || len(f.Description) != MaxString {
		t.Fatalf("long string: %d %v", len(f.Description), err)
	}
}

func TestCheckerRejectsInvalidRecords(t *testing.T) {
	c := NewChecker(testManifest.Normalized())
	cases := map[string]func() error{
		"missing title": func() error {
			_, err := c.Finding(ctis.Finding{Type: "misconfiguration", Severity: "high"})
			return err
		},
		"bad severity": func() error {
			_, err := c.Finding(ctis.Finding{Type: "misconfiguration", Title: "t", Severity: "apocalyptic"})
			return err
		},
		"asset no value": func() error { _, err := c.Asset(ctis.Asset{Type: "domain"}); return err },
		"unknown member": func() error {
			_, err := c.FindingJSON([]byte(`{"type":"misconfiguration","title":"t","severity":"high","evil":1}`))
			return err
		},
		"not json":      func() error { _, err := c.AssetJSON([]byte(`{"type":`)); return err },
		"trailing data": func() error { _, err := c.AssetJSON([]byte(`{"type":"domain","value":"a"} {}`)); return err },
		"dangling ref":  func() error { f := finding("t"); f.AssetRef = "nope"; _, err := c.Finding(f); return err },
		"too deep": func() error {
			_, err := c.InfoJSON([]byte(`{"properties":` + strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40) + `}`))
			return err
		},
		"bad coverage": func() error { _, err := c.InfoJSON([]byte(`{"metadata":{"coverage_type":"total"}}`)); return err },
		"info too large": func() error {
			_, err := c.InfoJSON([]byte(`{"properties":{"a":"` + strings.Repeat("x", MaxInfoBytes) + `"}}`))
			return err
		},
	}
	for name, fn := range cases {
		if err := fn(); !errors.Is(err, tool.ErrInvalidRecord) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Duplicate ids.
	if _, err := c.Asset(ctis.Asset{ID: "a1", Type: "domain", Value: "a.example"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Asset(ctis.Asset{ID: "a1", Type: "domain", Value: "b.example"}); !errors.Is(err, tool.ErrInvalidRecord) {
		t.Errorf("duplicate asset id: %v", err)
	}
	f := finding("t")
	f.AssetRef, f.ID = "a1", "f1"
	if _, err := c.Finding(f); err != nil {
		t.Fatalf("finding on an emitted asset: %v", err)
	}
	if _, err := c.Finding(f); !errors.Is(err, tool.ErrInvalidRecord) {
		t.Errorf("duplicate finding id: %v", err)
	}
}

func TestAssemblerStatusAndReport(t *testing.T) {
	m := testManifest.Normalized()
	task := tool.Task{ID: "t1", Targets: []tool.Target{
		{Ref: "a", Type: "http_service", Value: "https://a.example"},
		{Ref: "b", Type: "http_service", Value: "https://b.example"},
	}}
	asm := NewAssembler(m, task, NewChecker(m))
	if err := asm.Finding("a", finding("exposed")); err != nil {
		t.Fatal(err)
	}
	_ = asm.Target("a", tool.StateDone, nil)
	if st := asm.Status(nil); st != tool.StatusPartial {
		t.Fatalf("a target never reported must make the task partial, got %s", st)
	}
	_ = asm.Target("b", tool.StateFailed, &tool.Error{Class: tool.TargetUnreachable, Detail: "dial tcp: refused"})
	if st := asm.Status(nil); st != tool.StatusPartial {
		t.Fatalf("status %s", st)
	}
	if err := asm.Target("zzz", tool.StateDone, nil); err == nil {
		t.Fatal("an unknown target must be refused")
	}
	asm.SetInfo(&tool.ReportInfo{Tool: &ctis.Tool{Name: "nuclei-pretender", Version: "v9", Vendor: "Acme"},
		Metadata: &tool.ReportInfoMetadata{Properties: ctis.Properties{ProvenanceKey: "forged"}}})
	r := asm.Report(time.Unix(100, 0))
	if r.Tool.Name != "probe" || r.Tool.Version != "v9" || r.Tool.Vendor != "Acme" {
		t.Fatalf("tool %+v (the name must be the manifest's)", r.Tool)
	}
	if len(r.Assets) != 1 || r.Assets[0].ID != "target-a" || r.Findings[0].AssetRef != "target-a" {
		t.Fatalf("finding not filed on its target's asset: %+v %+v", r.Assets, r.Findings)
	}
	ft, _ := json.Marshal(r.Properties["failed_targets"])
	if !strings.Contains(string(ft), "b.example") || !strings.Contains(string(ft), "refused") {
		t.Fatalf("failed_targets %s", ft)
	}
	Stamp(r, Provenance{Tool: "probe", Status: tool.StatusPartial})
	if p, ok := r.Metadata.Properties[ProvenanceKey].(Provenance); !ok || p.Tool != "probe" {
		t.Fatalf("provenance not overwritten: %#v", r.Metadata.Properties[ProvenanceKey])
	}
	if err := r.Validate(); err != nil {
		t.Fatalf("assembled report invalid: %v", err)
	}
	if st := asm.Status(&tool.Error{Class: tool.Canceled}); st != tool.StatusCanceled {
		t.Fatal(st)
	}
	if st := asm.Status(&tool.Error{Class: tool.ToolError}); st != tool.StatusFailed {
		t.Fatal(st)
	}
}

func TestHTTPClientReachesOnlyAllowedHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://evil.example/", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()
	m := testManifest.Normalized()
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: srv.URL}}}
	c := NewHTTPClient(m, task)
	resp, err := c.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("target refused: %v", err)
	}
	_ = resp.Body.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port
	if _, err := c.Get(fmt.Sprintf("http://localhost:%d/", port)); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("another host name reached: %v", err)
	}
	if _, err := c.Get(srv.URL + "/redirect"); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("redirect off the target followed: %v", err)
	}
	// None: nothing at all.
	p := m
	p.Class, p.Consumes, p.Permissions.Network = tool.Parser, []string{"file:text/plain"}, tool.NetNone
	if _, err := NewHTTPClient(p, task).Get(srv.URL); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("network none reached the target: %v", err)
	}
	// A target that resolves to a metadata address is never dialed.
	meta := tool.Task{Targets: []tool.Target{{Ref: "m", Value: "http://169.254.169.254/"}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if _, err := NewHTTPClient(m, meta).Do(req); !errors.Is(err, ErrHostNotAllowed) {
		t.Fatalf("metadata address dialed: %v", err)
	}
}
