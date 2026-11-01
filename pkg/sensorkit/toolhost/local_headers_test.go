package toolhost

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ownerPolicy is a local policy with the sensor owner's identification.
type ownerPolicy struct {
	httpPolicy
	headers []core.LocalHTTPHeader
}

func (p *ownerPolicy) HTTPHeaders() []core.LocalHTTPHeader { return p.headers }

func owner(ua string, hs ...string) *ownerPolicy {
	p := &ownerPolicy{httpPolicy: httpPolicy{ua: ua, allowInsecure: true}}
	for i := 0; i+1 < len(hs); i += 2 {
		p.headers = append(p.headers, core.LocalHTTPHeader{Name: hs[i], Value: hs[i+1]})
	}
	return p
}

func prepareWith(t *testing.T, m tool.Manifest, pol Policy, org *core.OrgHTTPPolicy) (*prepared, *tool.Error) {
	t.Helper()
	task := httpTask
	task.OrgHTTP = org
	p, ierr, err := (&Host{Policy: pol}).prepare(context.Background(), m, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return p, ierr
}

func prepareWithTask(t *testing.T, m tool.Manifest, pol Policy, task tool.Task) (*prepared, *tool.Error) {
	t.Helper()
	p, ierr, err := (&Host{Policy: pol}).prepare(context.Background(), m, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return p, ierr
}

// The precedence table (research 375, 3.2), one row per case, for the
// layers this side owns: the job (the platform's merge of platform,
// organization and program layers), locked names, and the sensor owner.
func TestLocalHeadersPrecedence(t *testing.T) {
	m := targetHTTPManifest()
	cases := []struct {
		name   string
		org    *core.OrgHTTPPolicy
		pol    *ownerPolicy
		want   map[string]string
		wantUA string
	}{
		{"no job, local only", nil, owner("", "X-Netops", "dc1"), map[string]string{"X-Netops": "dc1"}, ""},
		{"job only", &core.OrgHTTPPolicy{Headers: map[string]string{"ATTT": "is-here"}}, owner(""), map[string]string{"ATTT": "is-here"}, ""},
		{"union of distinct names", &core.OrgHTTPPolicy{Headers: map[string]string{"ATTT": "is-here"}}, owner("", "X-Netops", "dc1"),
			map[string]string{"ATTT": "is-here", "X-Netops": "dc1"}, ""},
		{"local beats an unlocked job header, any case", &core.OrgHTTPPolicy{Headers: map[string]string{"X-Env": "uat"}}, owner("", "x-env", "dc1"),
			map[string]string{"x-env": "dc1"}, ""},
		{"locked job header beats local", &core.OrgHTTPPolicy{Headers: map[string]string{"X-Operator": "saas"}, LockedHeaders: []string{"x-operator"}},
			owner("", "X-OPERATOR", "mine", "X-Netops", "dc1"), map[string]string{"X-Operator": "saas", "X-Netops": "dc1"}, ""},
		{"local UA beats job UA", &core.OrgHTTPPolicy{UserAgent: "org"}, owner("local"), nil, "local"},
		{"locked job UA beats local UA", &core.OrgHTTPPolicy{UserAgent: "enforced", UserAgentLocked: true}, owner("local"), nil, "enforced"},
		{"job UA without local", &core.OrgHTTPPolicy{UserAgent: "org"}, owner(""), nil, "org"},
		{"local UA without job", nil, owner("local"), nil, "local"},
	}
	for _, c := range cases {
		p, ierr := prepareWith(t, m, c.pol, c.org)
		if ierr != nil {
			t.Fatalf("%s: %v", c.name, ierr)
		}
		var got map[string]string
		if p.task.Identity != nil {
			got = p.task.Identity.Headers
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: headers %v, want %v", c.name, got, c.want)
		}
		if c.wantUA != "" && (p.task.HTTP == nil || p.task.HTTP.UserAgent != c.wantUA) {
			t.Errorf("%s: user agent %+v, want %q", c.name, p.task.HTTP, c.wantUA)
		}
		for k, v := range c.want {
			if p.task.HTTP.Headers[k] != v {
				t.Errorf("%s: the tool's http settings lack %s: %v", c.name, k, p.task.HTTP.Headers)
			}
		}
	}
}

// A locked name the owner tried to change is reported not applied, with the
// reason; the job's value is the one sent.
func TestLocalHeadersLockedIsReported(t *testing.T) {
	p, ierr := prepareWith(t, targetHTTPManifest(), owner("", "X-Operator", "mine"),
		&core.OrgHTTPPolicy{Headers: map[string]string{"X-Operator": "saas"}, LockedHeaders: []string{"X-Operator"}})
	if ierr != nil {
		t.Fatal(ierr)
	}
	var sent, refused *tool.AppliedHeader
	for i := range p.applied.Headers {
		h := &p.applied.Headers[i]
		if h.Applied {
			sent = h
		} else {
			refused = h
		}
	}
	if sent == nil || sent.Value != "saas" || sent.Source != tool.SourceJobLocked {
		t.Fatalf("sent %+v", p.applied.Headers)
	}
	if refused == nil || refused.Source != tool.SourceSensor || !strings.Contains(refused.Reason, "locks") {
		t.Fatalf("refused %+v", p.applied.Headers)
	}
}

// Past the cap the task is refused with a message that names the cap and
// both sides; nothing is dropped. At the cap it runs.
func TestLocalHeadersCapOverflowRefuses(t *testing.T) {
	jobHeaders := map[string]string{}
	for i := 0; i < 10; i++ {
		jobHeaders[fmt.Sprintf("X-Job-%d", i)] = "v"
	}
	m := targetHTTPManifest()
	// 10 + 4 = 14: fits.
	p, ierr := prepareWith(t, m, owner("", "L1", "v", "L2", "v", "L3", "v", "L4", "v"), &core.OrgHTTPPolicy{Headers: jobHeaders})
	if ierr != nil || len(p.task.Identity.Headers) != 14 {
		t.Fatalf("14 headers: %v", ierr)
	}
	// A policy handing the sensor more local headers than the file allows
	// (not reachable through the file) must still be refused, never cut.
	var many []string
	for i := 0; i < 8; i++ {
		many = append(many, fmt.Sprintf("L%d", i), "v")
	}
	_, ierr = prepareWith(t, m, owner("", many...), &core.OrgHTTPPolicy{Headers: jobHeaders})
	if ierr == nil || ierr.Class != tool.RefusedByPolicy || !strings.Contains(ierr.Detail, "at most 16") || !strings.Contains(ierr.Detail, "local http.headers") {
		t.Fatalf("overflow: %+v", ierr)
	}
	// The same names as the job's replace, they do not add.
	same := owner("")
	for k := range jobHeaders {
		same.headers = append(same.headers, core.LocalHTTPHeader{Name: strings.ToLower(k), Value: "mine"})
	}
	if _, ierr := prepareWith(t, m, same, &core.OrgHTTPPolicy{Headers: jobHeaders}); ierr != nil {
		t.Fatalf("replacing is not adding: %v", ierr)
	}
}

// SECURITY: the sensor's local headers are validated again where they are
// used, whatever built the policy: a credential header, a control
// character or a bad name refuses the task.
func TestLocalHeadersValidatedAtUse(t *testing.T) {
	for _, h := range [][2]string{{"Authorization", "x"}, {"Cookie", "x"}, {"Host", "x"}, {"X-A", "a\r\nb: c"}, {"X A", "v"}, {"Proxy-X", "v"}} {
		_, ierr := prepareWith(t, targetHTTPManifest(), owner("", h[0], h[1]), nil)
		if ierr == nil || ierr.Class != tool.RefusedByPolicy {
			t.Errorf("%q accepted: %v", h[0], ierr)
		}
	}
}

// A shared sensor applies its local headers to every tenant's job and
// carries nothing of one tenant into another's: each task has exactly its
// own job's headers plus the host's.
func TestSharedSensorLocalHeadersNoCrossTenantValues(t *testing.T) {
	pol := owner("", "X-Netops", "dc1")
	m := targetHTTPManifest()
	tenantA := &core.OrgHTTPPolicy{Headers: map[string]string{"X-Tenant-Marker": "alpha-secret-marker"}, UserAgent: "alpha-ua"}
	tenantB := &core.OrgHTTPPolicy{Headers: map[string]string{"ATTT": "beta"}}
	var all []*prepared
	for _, org := range []*core.OrgHTTPPolicy{tenantA, tenantB, nil, tenantA, tenantB} {
		p, ierr := prepareWith(t, m, pol, org)
		if ierr != nil {
			t.Fatal(ierr)
		}
		all = append(all, p)
	}
	want := []map[string]string{
		{"X-Netops": "dc1", "X-Tenant-Marker": "alpha-secret-marker"},
		{"X-Netops": "dc1", "ATTT": "beta"},
		{"X-Netops": "dc1"},
		{"X-Netops": "dc1", "X-Tenant-Marker": "alpha-secret-marker"},
		{"X-Netops": "dc1", "ATTT": "beta"},
	}
	for i, p := range all {
		if !reflect.DeepEqual(p.task.Identity.Headers, want[i]) {
			t.Errorf("task %d: %v, want %v", i, p.task.Identity.Headers, want[i])
		}
		if i != 0 && i != 3 && (strings.Contains(fmt.Sprint(p.task.Identity, p.task.HTTP, p.applied), "alpha")) {
			t.Errorf("task %d carries tenant A values: %v %v", i, p.task.Identity, p.applied)
		}
	}
	// The host's headers never mutate the policy or a job.
	if len(pol.headers) != 1 || len(tenantA.Headers) != 1 || len(tenantB.Headers) != 1 {
		t.Fatal("a merge changed its inputs")
	}
}

// The owner's headers go only to tasks that send HTTP to their targets.
func TestLocalHeadersNotForPassiveTasks(t *testing.T) {
	m := httpManifest // network none: a passive source
	p, ierr := prepareWith(t, m, owner("", "X-Netops", "dc1"), nil)
	if ierr != nil {
		t.Fatal(ierr)
	}
	if p.task.Identity != nil || (p.task.HTTP != nil && len(p.task.HTTP.Headers) != 0) || p.applied != nil {
		t.Fatalf("a passive task got local headers: %+v %+v %+v", p.task.Identity, p.task.HTTP, p.applied)
	}
}

// With local headers set, a networked tool that cannot carry them never
// starts: nothing probes unmarked.
func TestLocalHeadersRefuseAToolThatCannotCarryThem(t *testing.T) {
	m := netManifest("{{target.value}}") // exec argv without a header placeholder
	_, ierr := prepareWith(t, m, owner("", "X-Netops", "dc1"), nil)
	if ierr == nil || ierr.Class != tool.RefusedByPolicy {
		t.Fatalf("want refused, got %v", ierr)
	}
	ok := netManifest("{{http.headers:-H}}", "{{target.value}}")
	if _, ierr := prepareWith(t, ok, owner("", "X-Netops", "dc1"), nil); ierr != nil {
		t.Fatal(ierr)
	}
}

// Tool-flag rendering as the built-in tools pass identification: nuclei
// takes -header "Name: value", httpx and katana take -H "Name: value". The
// local headers are in the list, locked job values win, UA first by tool.
func TestLocalHeadersRenderOnToolFlags(t *testing.T) {
	for _, c := range []struct{ name, flag string }{{"nuclei", "-header"}, {"httpx", "-H"}, {"katana", "-H"}} {
		m := netManifest("-ua", "{{http.user_agent}}", "{{http.headers:"+c.flag+"}}", "{{target.value}}")
		p, ierr := prepareWith(t, m, owner("dc1-scan", "X-Netops", "dc1", "X-Operator", "mine"),
			&core.OrgHTTPPolicy{Headers: map[string]string{"X-Operator": "saas", "ATTT": "is-here"}, LockedHeaders: []string{"X-Operator"}})
		if ierr != nil {
			t.Fatal(c.name, ierr)
		}
		got, ierr := expandArgv(m.Run.Argv, p)
		if ierr != nil {
			t.Fatal(ierr)
		}
		want := []string{"acme", "-ua", "dc1-scan", c.flag, "ATTT: is-here", c.flag, "X-Netops: dc1", c.flag, "X-Operator: saas", "x"}
		if !slices.Equal(got, want) {
			t.Errorf("%s: argv %q, want %q", c.name, got, want)
		}
	}
}

// The query parameter: a tool that declares features.http_query or passes
// {{http.query:-flag}} carries it; any other tool reports it not applied,
// and the task still runs. Never silent.
func TestQueryParameterAppliedOrReportedNotApplied(t *testing.T) {
	org := &core.OrgHTTPPolicy{Query: &core.HTTPQuery{Name: "scan", Value: "acme-1"}}

	// Exec tool with the placeholder.
	m := netManifest("{{http.query:--param}}", "{{target.value}}")
	p, ierr := prepareWith(t, m, nil, org)
	if ierr != nil {
		t.Fatal(ierr)
	}
	got, _ := expandArgv(m.Run.Argv, p)
	if want := []string{"acme", "--param", "scan=acme-1", "x"}; !slices.Equal(got, want) {
		t.Fatalf("argv %q, want %q", got, want)
	}
	if q := p.applied.Query; q == nil || !q.Applied || q.Name != "scan" || q.Value != "acme-1" {
		t.Fatalf("applied %+v", p.applied)
	}
	// No query: the placeholder leaves nothing on the argv.
	p, _ = prepareWith(t, m, nil, nil)
	if got, _ := expandArgv(m.Run.Argv, p); !slices.Equal(got, []string{"acme", "x"}) {
		t.Fatalf("argv without a query %q", got)
	}

	// Declared feature.
	d := targetHTTPManifest()
	d.Features = &tool.Features{HTTPIdentity: true, HTTPQuery: true}
	if p, ierr := prepareWith(t, d, nil, org); ierr != nil || p.task.Identity.Query == nil || !p.applied.Query.Applied {
		t.Fatalf("declared: %v %+v", ierr, p)
	}

	// A tool without it: runs, reports not applied, the tool never sees it.
	n := targetHTTPManifest()
	p, ierr = prepareWith(t, n, nil, org)
	if ierr != nil {
		t.Fatalf("a tool without http_query must still run: %v", ierr)
	}
	q := p.applied.Query
	if q == nil || q.Applied || !strings.Contains(q.Reason, "http_query") || p.task.Identity != nil {
		t.Fatalf("not applied: %+v identity %+v", q, p.task.Identity)
	}
}

// ctx.HTTP appends the query parameter to every request URL, replacing one
// of the same name, and keeps the others.
func TestQueryParameterOnContextHTTP(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.RawQuery)
	}))
	defer srv.Close()
	m := targetHTTPManifest()
	m.Features = &tool.Features{HTTPIdentity: true, HTTPQuery: true}
	m.Consumes = []string{"domain"}
	task := httpTask
	task.Targets = []tool.Target{{Ref: "d", Type: "domain", Value: "127.0.0.1"}}
	task.OrgHTTP = &core.OrgHTTPPolicy{Query: &core.HTTPQuery{Name: "scan", Value: "acme-1"}}
	p, ierr := prepareWithTask(t, m, nil, task)
	if ierr != nil {
		t.Fatal(ierr)
	}
	c := toolrt.NewHTTPClient(m, p.task)
	for _, u := range []string{srv.URL + "/a", srv.URL + "/b?x=1", srv.URL + "/c?scan=evil&scan=2"} {
		resp, err := c.Get(u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	want := []string{"scan=acme-1", "scan=acme-1&x=1", "scan=acme-1"}
	if !slices.Equal(seen, want) {
		t.Fatalf("queries %q, want %q", seen, want)
	}
}

// The applied report: where each value came from, secret-looking values
// masked, and the user agent with its source.
func TestAppliedIdentityReport(t *testing.T) {
	p, ierr := prepareWith(t, targetHTTPManifest(), owner("dc1-scan", "X-Netops", "dc1", "X-Scan-Token", "s3cr3t"),
		&core.OrgHTTPPolicy{Headers: map[string]string{"X-Operator": "saas"}, LockedHeaders: []string{"X-Operator"}, UserAgent: "org-ua"})
	if ierr != nil {
		t.Fatal(ierr)
	}
	a := p.applied
	if a.Tool != "acme-cli" || a.UserAgent != "dc1-scan" || a.UserAgentSource != tool.SourceSensor {
		t.Fatalf("applied %+v", a)
	}
	got := map[string]tool.AppliedHeader{}
	for _, h := range a.Headers {
		got[h.Name] = h
	}
	if got["X-Operator"].Source != tool.SourceJobLocked || got["X-Netops"].Source != tool.SourceSensor || got["X-Netops"].Value != "dc1" {
		t.Fatalf("headers %+v", a.Headers)
	}
	if got["X-Scan-Token"].Value != tool.Masked || strings.Contains(fmt.Sprint(a), "s3cr3t") {
		t.Fatalf("a secret-looking value must be masked: %+v", got["X-Scan-Token"])
	}
	// The real value is what is sent.
	if p.task.Identity.Headers["X-Scan-Token"] != "s3cr3t" {
		t.Fatal("masking must only touch the report")
	}
	// Nothing configured: no report.
	if p, _ := prepareWith(t, targetHTTPManifest(), owner(""), nil); p.applied != nil {
		t.Fatalf("empty identity reported: %+v", p.applied)
	}
}

func TestMaskIdentityValue(t *testing.T) {
	for name, masked := range map[string]bool{"X-Api-Key": true, "X-Auth": true, "Session-Id": true, "X-Token": true, "ATTT": false, "X-Netops": false, "X-Operator": false} {
		got := tool.MaskIdentityValue(name, "v")
		if (got == tool.Masked) != masked {
			t.Errorf("%s: %q", name, got)
		}
	}
}

// The platform matches one capability for the whole identification feature;
// there is no second version of it.
func TestOneIdentityCapability(t *testing.T) {
	if CapabilityHTTPIdentity != "http.identity@1" {
		t.Fatalf("capability %q: the platform matches http.identity@1", CapabilityHTTPIdentity)
	}
}
