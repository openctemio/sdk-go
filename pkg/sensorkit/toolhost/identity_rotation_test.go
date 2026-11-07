package toolhost

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openctemio/contract/identity"
	"github.com/openctemio/ctis/v2"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func uaList(prefix string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s/%d", prefix, i)
	}
	return out
}

// ownerList is a local policy with the sensor owner's rotation list.
type ownerList struct {
	httpPolicy
	list []string
}

func (p *ownerList) HTTPUserAgents() []string { return p.list }

func webTask(org *core.OrgHTTPPolicy, targets ...string) tool.Task {
	task := tool.Task{OrgHTTP: org}
	for i, v := range targets {
		task.Targets = append(task.Targets, tool.Target{Ref: fmt.Sprintf("t%d", i), Type: "domain_name", Value: v})
	}
	return task
}

func webTarget() tool.Manifest {
	m := targetHTTPManifest()
	m.Consumes = []string{"domain_name"}
	return m
}

// A rotation list travels whole with its key: the tool's single value is
// the task host's own, the applied report names the pool and the layer.
func TestRotationListIsStickyPerRunAndHost(t *testing.T) {
	list := uaList("job", 50)
	org := &core.OrgHTTPPolicy{UserAgent: list[0], UserAgents: list, UserAgentKey: "run-1"}
	p, ierr := prepareWithTask(t, webTarget(), nil, webTask(org, "www.example.com"))
	if ierr != nil {
		t.Fatal(ierr)
	}
	want := identity.SelectUserAgent("run-1", "www.example.com", list)
	id := p.task.Identity
	if id == nil || id.UserAgent != want || len(id.UserAgents) != 50 || id.UserAgentKey != "run-1" {
		t.Fatalf("identity: %+v", id)
	}
	if p.task.HTTP == nil || p.task.HTTP.UserAgent != want {
		t.Fatalf("http: %+v", p.task.HTTP)
	}
	a := p.applied
	if a == nil || a.UserAgent != want || a.UserAgentSource != tool.SourceJob || a.UserAgentPool != 50 || a.UserAgentReason != "" {
		t.Fatalf("applied: %+v", a)
	}
	// Another task of the same run on the same host gets the same value.
	p2, _ := prepareWithTask(t, webTarget(), nil, webTask(org, "https://WWW.example.com:8443/x"))
	if p2.task.Identity.UserAgent != want {
		t.Fatalf("same run, same host: %q, want %q", p2.task.Identity.UserAgent, want)
	}
}

// Lock semantics of a list: replaced whole by the more specific layer,
// never merged; the sensor owner's list or User-Agent wins over the job's
// unless the job locks it.
func TestRotationListLockSemantics(t *testing.T) {
	job := uaList("job", 5)
	local := uaList("owner", 3)
	cases := []struct {
		name   string
		pol    Policy
		org    *core.OrgHTTPPolicy
		pool   []string
		source string
	}{
		{"owner list over an unlocked job list", &ownerList{httpPolicy: httpPolicy{allowInsecure: true}, list: local},
			&core.OrgHTTPPolicy{UserAgent: job[0], UserAgents: job, UserAgentKey: "k"}, local, tool.SourceSensor},
		{"locked job list over the owner's list", &ownerList{httpPolicy: httpPolicy{allowInsecure: true}, list: local},
			&core.OrgHTTPPolicy{UserAgent: job[0], UserAgents: job, UserAgentKey: "k", UserAgentLocked: true}, job, tool.SourceJobLocked},
		{"locked job list over the owner's single User-Agent", &httpPolicy{ua: "owner-one", allowInsecure: true},
			&core.OrgHTTPPolicy{UserAgent: job[0], UserAgents: job, UserAgentKey: "k", UserAgentLocked: true}, job, tool.SourceJobLocked},
		{"owner single User-Agent over an unlocked list", &httpPolicy{ua: "owner-one", allowInsecure: true},
			&core.OrgHTTPPolicy{UserAgent: job[0], UserAgents: job, UserAgentKey: "k"}, []string{"owner-one"}, tool.SourceSensor},
		{"owner list without a job User-Agent", &ownerList{httpPolicy: httpPolicy{allowInsecure: true}, list: local},
			&core.OrgHTTPPolicy{Headers: map[string]string{"X-Scan": "1"}, UserAgentKey: "k"}, local, tool.SourceSensor},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ierr := prepareWithTask(t, webTarget(), c.pol, webTask(c.org, "www.example.com"))
			if ierr != nil {
				t.Fatal(ierr)
			}
			want := identity.SelectUserAgent("k", "www.example.com", c.pool)
			if p.applied.UserAgent != want || p.applied.UserAgentSource != c.source {
				t.Fatalf("applied %q from %s, want %q from %s", p.applied.UserAgent, p.applied.UserAgentSource, want, c.source)
			}
			if len(c.pool) > 1 && len(p.task.Identity.UserAgents) != len(c.pool) {
				t.Fatalf("list: %v", p.task.Identity.UserAgents)
			}
		})
	}
}

// Through the SDK HTTP client every request carries its own host's value,
// with the identification header beside it (rotation never drops it).
func TestRotationPerHostOnContextHTTP(t *testing.T) {
	var mu sync.Mutex
	seen := map[string][]string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		seen[r.Host] = append(seen[r.Host], r.UserAgent()+"|"+r.Header.Get("X-Pentest-Id"))
	}))
	defer srv.Close()
	list := uaList("job", 40)
	org := &core.OrgHTTPPolicy{UserAgent: list[0], UserAgents: list, UserAgentKey: "run-7",
		Headers: map[string]string{"X-Pentest-Id": "pt-1"}, IdentificationRequired: true}
	p, ierr := prepareWithTask(t, webTarget(), nil, webTask(org, "127.0.0.1", "localhost"))
	if ierr != nil {
		t.Fatal(ierr)
	}
	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	c := toolrt.NewHTTPClient(webTarget(), p.task)
	for range 3 {
		for _, h := range []string{"127.0.0.1", "localhost"} {
			req, _ := http.NewRequest(http.MethodGet, "http://"+h+port+"/", nil)
			req.Header.Set("User-Agent", "tool-own/1")
			resp, err := c.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()
		}
	}
	for _, h := range []string{"127.0.0.1", "localhost"} {
		want := identity.SelectUserAgent("run-7", h, list) + "|pt-1"
		got := seen[h+port]
		if len(got) != 3 {
			t.Fatalf("%s: %d requests", h, len(got))
		}
		for _, g := range got {
			if g != want {
				t.Fatalf("%s: request carried %q, want %q", h, g, want)
			}
		}
	}
}

// What a tool that cannot set a User-Agent does is recorded, not silent.
func TestUserAgentGapIsRecorded(t *testing.T) {
	m := netManifest("-u", "{{target.value}}")
	m.Consumes = []string{"domain_name"}
	p, ierr := prepareWithTask(t, m, &ownerList{httpPolicy: httpPolicy{allowInsecure: true}, list: uaList("owner", 3)}, webTask(nil, "www.example.com"))
	if ierr != nil {
		t.Fatal(ierr)
	}
	if p.applied == nil || !strings.Contains(p.applied.UserAgentReason, "cannot set a User-Agent") {
		t.Fatalf("applied: %+v", p.applied)
	}
}

// SECURITY: required identification fails closed. Every row is refused
// before any task directory or process exists.
func TestRequiredIdentificationRefusesWhatCannotCarryIt(t *testing.T) {
	q := &core.HTTPQuery{Name: "pentest_id", Value: "pt-1"}
	hdr := map[string]string{"X-Pentest-Id": "pt-1"}
	noQuery := webTarget() // http_identity, no http_query
	execNone := netManifest("-u", "{{target.value}}")
	execNone.Consumes = []string{"domain_name"}
	cases := []struct {
		name string
		m    tool.Manifest
		org  *core.OrgHTTPPolicy
		want string
	}{
		{"required with nothing to carry", webTarget(), &core.OrgHTTPPolicy{IdentificationRequired: true, UserAgents: uaList("a", 3), UserAgentKey: "k"}, "carries no identification header or query parameter"},
		{"required query, tool without http_query", noQuery, &core.OrgHTTPPolicy{IdentificationRequired: true, Query: q}, "cannot carry the query parameter pentest_id"},
		{"required header, exec tool without header flags", execNone, &core.OrgHTTPPolicy{IdentificationRequired: true, Headers: hdr}, "cannot send the job's identification"},
		{"required header and query, tool carries only headers", noQuery, &core.OrgHTTPPolicy{IdentificationRequired: true, Headers: hdr, Query: q}, "cannot carry the query parameter"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, ierr := prepareWithTask(t, c.m, nil, webTask(c.org, "www.example.com"))
			if ierr == nil || ierr.Class != tool.RefusedByPolicy || !strings.Contains(ierr.Error(), c.want) {
				t.Fatalf("got %v, want refused_by_policy %q", ierr, c.want)
			}
		})
	}
	// Not required: the query parameter the tool cannot carry is reported
	// not applied and the task runs (scan runs what is supported).
	p, ierr := prepareWithTask(t, noQuery, nil, webTask(&core.OrgHTTPPolicy{Query: q}, "www.example.com"))
	if ierr != nil || p.applied.Query == nil || p.applied.Query.Applied {
		t.Fatalf("not required: %v %+v", ierr, p.applied)
	}
	// Required, and the tool carries both: it runs, reported required.
	both := webTarget()
	both.Features = &tool.Features{HTTPIdentity: true, HTTPQuery: true}
	p, ierr = prepareWithTask(t, both, nil, webTask(&core.OrgHTTPPolicy{IdentificationRequired: true, Headers: hdr, Query: q}, "www.example.com"))
	if ierr != nil || !p.applied.Required || p.applied.Carrier != tool.CarrierTool || p.inject != nil {
		t.Fatalf("carried by the tool: %v %+v", ierr, p.applied)
	}
}

// On a sandbox that confines the network the forwarder carries what the
// tool cannot: the task runs and the forwarder is told what to add.
func TestRequiredIdentificationCarriedByTheForwarder(t *testing.T) {
	m := webTarget()
	m.Features = nil // carries nothing itself
	m.Run = nil
	org := &core.OrgHTTPPolicy{IdentificationRequired: true, Headers: map[string]string{"X-Pentest-Id": "pt-1"},
		Query: &core.HTTPQuery{Name: "pentest_id", Value: "pt-1"}, UserAgent: "a/0", UserAgents: uaList("a", 4), UserAgentKey: "run-1"}
	h := &Host{Backend: statusBackend{st: executor.Status{NetworkEnforced: true}}}
	p, ierr, err := h.prepare(context.Background(), m, webTask(org, "www.example.com", "api.example.com"), RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	if p.inject == nil || p.inject.Headers["X-Pentest-Id"] != "pt-1" || p.inject.QueryName != "pentest_id" || p.inject.UserAgent == nil {
		t.Fatalf("inject: %+v", p.inject)
	}
	if got, want := p.inject.UserAgent("api.example.com"), identity.SelectUserAgent("run-1", "api.example.com", org.UserAgents); got != want {
		t.Fatalf("forwarder User-Agent %q, want %q", got, want)
	}
	if p.applied.Carrier != tool.CarrierForwarder || !p.applied.Required || p.applied.UserAgentReason != "" {
		t.Fatalf("applied: %+v", p.applied)
	}
	// The same task on a sandbox that does not confine the network is
	// refused.
	open := &Host{Backend: statusBackend{st: executor.Status{}}}
	if _, ierr, _ := open.prepare(context.Background(), m, webTask(org, "www.example.com"), RunOptions{}); ierr == nil {
		t.Fatal("an unconfined sandbox ran a task whose identification only the forwarder could add")
	}
	// startEgress never runs an injected task without its forwarder.
	if _, err := h.startEgress(context.Background(), statusBackend{st: executor.Status{}}, p); err == nil {
		t.Fatal("startEgress ran an injected task without a forwarder")
	}
}

// identDialTool fetches every target through ctx.HTTP (so it carries the
// identification headers) but cannot carry a query parameter.
var identDialTool = tool.New(tool.Manifest{
	Name: "ident-dial-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Produces: []string{"finding:misconfiguration"}, Permissions: tool.Permissions{Network: tool.NetTargets},
	Features: &tool.Features{HTTPIdentity: true},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	c := ctx.HTTP()
	c.Timeout = 5 * time.Second
	for _, tg := range task.Targets {
		resp, err := c.Get(tg.Value)
		if err != nil {
			ctx.TargetError(tg, tool.Unreachable(err))
			continue
		}
		_ = resp.Body.Close()
		if err := ctx.Emit().Finding(tg, ctis.Finding{Type: "misconfiguration", RuleID: "seen", Title: "fetched " + tg.Ref, Severity: "info"}); err != nil {
			return err
		}
		ctx.TargetDone(tg)
	}
	return nil
})

// SECURITY: required on and no way to apply it: zero requests leave. The
// tool runs out of process and would fetch its target (the control run
// without the requirement reaches the server); with the requirement the
// target sees no connection at all.
func TestRequiredIdentificationZeroRequestsLeave(t *testing.T) {
	srv, hits := recorder(t)
	h := testHost(t)
	// Nothing confines the network: the forwarder cannot add the query
	// parameter. The task is refused before the backend is asked for
	// anything (statusBackend has no Prepare).
	h.Backend = statusBackend{st: executor.Status{}}
	q := &core.HTTPQuery{Name: "pentest_id", Value: "pt-1"}
	task := tool.Task{ID: "req-1", Targets: []tool.Target{{Ref: "t", Type: "web_origin", Value: srv.URL}},
		OrgHTTP: &core.OrgHTTPPolicy{IdentificationRequired: true, Headers: map[string]string{"X-Pentest-Id": "pt-1"}, Query: q}}
	out, err := h.RunBuiltin(context.Background(), identDialTool, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err == nil || out.Err.Class != tool.RefusedByPolicy {
		t.Fatalf("want refused_by_policy, got %+v", out.Err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("required identification could not be applied, yet the target saw %d connection(s)", n)
	}
	// Control: without the requirement the same tool reaches the target
	// (the query parameter is reported not applied).
	h.Backend = nil // the host's own sandbox: a real run
	task.ID = "req-2"
	task.OrgHTTP = &core.OrgHTTPPolicy{Headers: map[string]string{"X-Pentest-Id": "pt-1"}, Query: q}
	out, err = h.RunBuiltin(context.Background(), identDialTool, task, RunOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Err != nil {
		t.Fatalf("control run: %+v (stderr %s)", out.Err, out.Stderr)
	}
	if hits.Load() == 0 {
		t.Fatal("control run never reached the target: the test proves nothing")
	}
	if out.Identity == nil || out.Identity.Query == nil || out.Identity.Query.Applied {
		t.Fatalf("control run identity: %+v", out.Identity)
	}
}
