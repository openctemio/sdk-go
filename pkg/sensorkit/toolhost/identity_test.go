package toolhost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// netManifest is a networked exec tool; argv decides what it can pass on.
func netManifest(argv ...string) tool.Manifest {
	m := httpManifest
	m.Permissions = tool.Permissions{Network: tool.NetTargets}
	m.Run = &tool.RunSpec{Profile: tool.ProfileExec, Argv: append([]string{"acme"}, argv...), Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}}
	return m
}

func identityTask() tool.Task {
	task := httpTask
	task.OrgHTTP = &core.OrgHTTPPolicy{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe"}}
	return task
}

// SECURITY: a job that carries an identification (a bug-bounty program's
// User-Agent and headers) never starts a networked tool that could probe
// without it. An exec tool must pass both on its argv; any other tool must
// declare features.http_identity. A tool that can, receives it.
func TestIdentityReachesTheToolOrTheTaskIsRefused(t *testing.T) {
	ctx := context.Background()
	h := &Host{}
	cases := []struct {
		name   string
		m      tool.Manifest
		refuse bool
	}{
		{"exec tool passing neither", netManifest("-u", "{{target.value}}"), true},
		{"exec tool passing only the User-Agent", netManifest("-ua", "{{http.user_agent}}"), true},
		{"exec tool passing only the headers", netManifest("{{http.headers:-H}}"), true},
		{"exec tool passing both", netManifest("-ua", "{{http.user_agent}}", "{{http.headers:-H}}"), false},
	}
	compiled := httpManifest
	compiled.Permissions = tool.Permissions{Network: tool.NetTargets}
	compiled.Run = nil
	cases = append(cases, struct {
		name   string
		m      tool.Manifest
		refuse bool
	}{"compiled tool without features.http_identity", compiled, true})
	declared := compiled
	declared.Features = &tool.Features{HTTPIdentity: true}
	cases = append(cases, struct {
		name   string
		m      tool.Manifest
		refuse bool
	}{"compiled tool declaring features.http_identity", declared, false})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ierr, err := h.prepare(ctx, c.m, identityTask(), RunOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if c.refuse {
				if ierr == nil || ierr.Class != tool.RefusedByPolicy {
					t.Fatalf("want refused_by_policy, got %v", ierr)
				}
				return
			}
			if ierr != nil {
				t.Fatalf("refused: %v", ierr)
			}
			id := p.task.Identity
			if id == nil || id.UserAgent != "jdoe-research" || id.Headers["X-Bug-Bounty"] != "jdoe" {
				t.Fatalf("identity: %+v", id)
			}
		})
	}
}

// The exec tool's argv carries the identification: the User-Agent and one
// flag plus "Name: value" per header, in name order, and nothing else.
func TestIdentityOnTheExecArgv(t *testing.T) {
	m := netManifest("-ua", "{{http.user_agent}}", "{{http.headers:-H}}", "{{target.value}}")
	m.HTTP = &tool.HTTPSpec{Headers: map[string]string{"Accept": "*/*"}}
	p, ierr, err := (&Host{}).prepare(context.Background(), m, identityTask(), RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	got, ierr := expandArgv(m.Run.Argv, p)
	if ierr != nil {
		t.Fatal(ierr)
	}
	want := []string{"acme", "-ua", "jdoe-research", "-H", "Accept: */*", "-H", "X-Bug-Bounty: jdoe", "x"}
	if !slices.Equal(got, want) {
		t.Fatalf("argv %q, want %q", got, want)
	}
}

// Without an identification nothing is refused, and a tool that runs
// without a network is never refused.
func TestNoIdentityNoRefusal(t *testing.T) {
	ctx := context.Background()
	if _, ierr, err := (&Host{}).prepare(ctx, netManifest("-u", "{{target.value}}"), httpTask, RunOptions{}); err != nil || ierr != nil {
		t.Fatalf("no identification: %v %v", err, ierr)
	}
	offline := httpManifest // network none
	if _, ierr, err := (&Host{}).prepare(ctx, offline, identityTask(), RunOptions{}); err != nil || ierr != nil {
		t.Fatalf("offline tool: %v %v", err, ierr)
	}
}

// The header list is a whole argument; inside a larger one the manifest is
// invalid.
func TestHeaderListMustBeWholeArgument(t *testing.T) {
	m := netManifest("-H={{http.headers:-H}}")
	if err := m.Validate(); err == nil {
		t.Fatal("a header list inside an argument was accepted")
	}
	if err := netManifest("{{http.headers:-H}}").Validate(); err != nil {
		t.Fatalf("whole header list: %v", err)
	}
}

// The identification is HTTP headers: a tool that reaches its targets
// without HTTP (a port scan, DNS) or reaches no target (a vendor API, the
// resolver) is not refused for it; a tool that implements nothing is.
func TestIdentityOnlyForHTTPTools(t *testing.T) {
	impl := func(caps ...string) []tool.Implementation {
		out := make([]tool.Implementation, 0, len(caps))
		for _, c := range caps {
			out = append(out, tool.Implementation{Capability: c})
		}
		return out
	}
	withNet := func(n tool.Network, caps ...string) tool.Manifest {
		m := tool.Manifest{Name: "x", Permissions: tool.Permissions{Network: n}, Implements: impl(caps...)}
		return m
	}
	cases := []struct {
		name string
		m    tool.Manifest
		cap  string
		want bool
	}{
		{"port scanner", withNet(tool.NetTargets, "scan.ports@1"), "", false},
		{"host discovery and DNS", withNet(tool.NetTargets, "discover.hosts@1", "resolve.dns@1"), "", false},
		{"http prober", withNet(tool.NetTargets, "probe.http@1"), "", true},
		{"port scanner that also probes http", withNet(tool.NetTargets, "scan.ports@1", "probe.http@1"), "", true},
		{"its port-scan task", withNet(tool.NetTargets, "scan.ports@1", "probe.http@1"), "scan.ports@1", false},
		{"its http task", withNet(tool.NetTargets, "scan.ports@1", "probe.http@1"), "probe.http@1", true},
		{"implements nothing (fail closed)", withNet(tool.NetTargets), "", true},
		{"target-reaching subdomain discovery (vhost probing)", withNet(tool.NetTargets, "discover.subdomains@1"), "", true},
		{"target-reaching lookup", withNet(tool.NetTargets, "lookup.rdap@1"), "lookup.rdap@1", true},
		{"passive subdomain sources", withNet(tool.NetEgressProxy, "discover.subdomains@1"), "", false},
		{"egress proxy (registries, repositories)", withNet(tool.NetEgressProxy, "sca.deps@1"), "", false},
		{"vendor API", withNet(tool.NetVendor, "discover.subdomains@1"), "", false},
		{"resolver", withNet(tool.NetResolver, "resolve.dns@1"), "", false},
		{"no network", withNet(tool.NetNone, "sast.code@1"), "", false},
	}
	for _, c := range cases {
		if got := sendsHTTPToTargets(c.m, tool.Task{Capability: c.cap}); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// HeaderLines and Overrides are what a tool that maps the identification
// onto its own flags uses.
func TestIdentityHeaderLines(t *testing.T) {
	id := &tool.Identity{UserAgent: "jdoe-research", Headers: map[string]string{"X-Bug-Bounty": "jdoe", "A-First": "1"}}
	got := id.HeaderLines()
	want := []string{"User-Agent: jdoe-research", "A-First: 1", "X-Bug-Bounty: jdoe"}
	if !slices.Equal(got, want) {
		t.Fatalf("%q", got)
	}
	if !id.Overrides("user-agent: other") || !id.Overrides("x-bug-bounty:someone") || id.Overrides("X-Scan: 1") {
		t.Fatal("Overrides")
	}
	var none *tool.Identity
	if none.HeaderLines() != nil || none.Overrides("User-Agent: x") {
		t.Fatal("nil identity")
	}
}

// SECURITY: an identification is checked where the task is built. CR/LF
// in a value, a name that is not a token, a credential or connection header
// and too many headers each refuse the task with refused_by_policy; nothing
// is stripped, and nothing reaches a request or an argv.
func TestIdentityIsValidatedAtTheBoundary(t *testing.T) {
	m := netManifest("-ua", "{{http.user_agent}}", "{{http.headers:-H}}")
	many := map[string]string{}
	for i := range 11 {
		many["X-H"+string(rune('a'+i))] = "1"
	}
	cases := map[string]*core.OrgHTTPPolicy{
		"CRLF in a value":      {Headers: map[string]string{"X-Bug-Bounty": "jdoe\r\nX-Evil: 1"}},
		"NUL in a value":       {Headers: map[string]string{"X-Bug-Bounty": "jdoe\x00"}},
		"LF in the User-Agent": {UserAgent: "jdoe\nGET / HTTP/1.1"},
		"name not a token":     {Headers: map[string]string{"X Bug: Bounty": "jdoe"}},
		"Host":                 {Headers: map[string]string{"Host": "evil.example"}},
		"Authorization":        {Headers: map[string]string{"Authorization": "Bearer x"}},
		"Transfer-Encoding":    {Headers: map[string]string{"Transfer-Encoding": "chunked"}},
		"Proxy-* header":       {Headers: map[string]string{"Proxy-Foo": "1"}},
		"too many headers":     {Headers: many},
		"value too long":       {Headers: map[string]string{"X-Bug-Bounty": string(make([]byte, 201))}},
	}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			task := httpTask
			task.OrgHTTP = pol
			_, ierr, err := (&Host{}).prepare(context.Background(), m, task, RunOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if ierr == nil || ierr.Class != tool.RefusedByPolicy {
				t.Fatalf("want refused_by_policy, got %v", ierr)
			}
		})
	}
}

// SECURITY: whatever built the task's settings, a hostile header never
// becomes more than one argv element: expansion refuses it.
func TestHeaderArgsRefuseHostileValues(t *testing.T) {
	for _, h := range []map[string]string{
		{"X-Bug-Bounty": "jdoe\r\nX-Evil: 1"},
		{"X-Bug-Bounty": "jdoe\x00"},
		{"Bad Name": "1"},
	} {
		p := &prepared{m: netManifest("{{http.headers:-H}}"), task: tool.Task{HTTP: &tool.HTTPSpec{Headers: h}}}
		if got, ierr := expandArgv(p.m.Run.Argv, p); ierr == nil || ierr.Class != tool.RefusedByPolicy {
			t.Fatalf("%q expanded to %q", h, got)
		}
	}
	p := &prepared{m: netManifest("{{http.headers:-H}}"), task: tool.Task{HTTP: &tool.HTTPSpec{Headers: map[string]string{"X-Bug-Bounty": "jdoe; a=b"}}}}
	got, ierr := expandArgv(p.m.Run.Argv, p)
	if ierr != nil || !slices.Equal(got, []string{"acme", "-H", "X-Bug-Bounty: jdoe; a=b"}) {
		t.Fatalf("a plain value: %q %v", got, ierr)
	}
}

// SECURITY: the identification goes only to a task that sends HTTP to its
// targets. A DNS resolver, a passive subdomain source behind the egress
// proxy or a port scan is admitted with no identification at all: it is
// not refused for one, and never hands the program's headers to a third
// party. A tool that sends HTTP to its targets still receives it.
func TestIdentityClearedForTasksWithoutHTTPToTargets(t *testing.T) {
	ctx := context.Background()
	compiled := func(n tool.Network, caps ...string) tool.Manifest {
		m := httpManifest
		m.Run = nil
		m.Tier = tool.T1
		m.Consumes = []string{"domain"}
		m.Produces = []string{"asset:domain"}
		if n == tool.NetTargets {
			m.Produces = []string{"asset:host"}
			if caps[0] == "probe.http@1" {
				m.Produces = []string{"asset:http_service"}
			}
		}
		m.Permissions = tool.Permissions{Network: n}
		m.Implements = nil
		for _, c := range caps {
			m.Implements = append(m.Implements, tool.Implementation{Capability: c})
		}
		return m
	}
	cases := []struct {
		name     string
		m        tool.Manifest
		capab    string
		identity bool
	}{
		{"resolver (dnsx)", compiled(tool.NetResolver, "resolve.dns@1"), "resolve.dns@1", false},
		{"passive sources (subfinder)", compiled(tool.NetEgressProxy, "discover.subdomains@1"), "discover.subdomains@1", false},
		{"port scan (naabu)", compiled(tool.NetTargets, "scan.ports@1", "discover.hosts@1"), "scan.ports@1", false},
		{"port scan, no capability named", compiled(tool.NetTargets, "scan.ports@1", "discover.hosts@1"), "", false},
	}
	declared := compiled(tool.NetTargets, "probe.http@1")
	declared.Features = &tool.Features{HTTPIdentity: true}
	cases = append(cases, struct {
		name     string
		m        tool.Manifest
		capab    string
		identity bool
	}{"http prober declaring features.http_identity", declared, "probe.http@1", true})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			task := identityTask()
			task.Targets = []tool.Target{{Ref: "d", Type: "domain", Value: "example.com"}}
			task.Capability = c.capab
			p, ierr, err := (&Host{}).prepare(ctx, c.m, task, RunOptions{})
			if err != nil || ierr != nil {
				t.Fatalf("refused: %v %v", err, ierr)
			}
			if got := !p.task.Identity.Empty(); got != c.identity {
				t.Fatalf("identity handed to the tool: %v, want %v (%+v)", got, c.identity, p.task.Identity)
			}
		})
	}
}

// SECURITY: what a task that sends no HTTP to its targets actually SENDS
// carries none of the organization's identification. A passive-source tool
// requesting through Context.HTTP sends neither the program's User-Agent
// nor its headers to the source, and an exec tool's {{http.user_agent}}
// and {{http.headers:-flag}} expand without them. The tool's own headers
// still go; a tool that sends HTTP to its targets still sends the
// identification (the control).
func TestNoIdentificationSentToThirdParties(t *testing.T) {
	type seen struct{ ua, bounty, own string }
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append(got, seen{r.UserAgent(), r.Header.Get("X-Bug-Bounty"), r.Header.Get("X-Tool")})
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	send := func(t *testing.T, m tool.Manifest, capab string) seen {
		t.Helper()
		task := identityTask()
		// The request goes to the test server, the one host the tool's
		// network permission lets it dial here.
		task.Targets = []tool.Target{{Ref: "d", Type: "domain", Value: "127.0.0.1"}}
		task.Capability = capab
		p, ierr, err := (&Host{}).prepare(context.Background(), m, task, RunOptions{})
		if err != nil || ierr != nil {
			t.Fatalf("refused: %v %v", err, ierr)
		}
		got = nil
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/q", nil)
		resp, err := toolrt.NewHTTPClient(m, p.task).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if len(got) != 1 {
			t.Fatalf("requests seen: %d", len(got))
		}
		return got[0]
	}
	compiled := func(n tool.Network, capab, produces string) tool.Manifest {
		m := httpManifest
		m.Run = nil
		m.Tier = tool.T1
		m.Consumes = []string{"domain"}
		m.Produces = []string{produces}
		m.Permissions = tool.Permissions{Network: n}
		m.Implements = []tool.Implementation{{Capability: capab}}
		m.HTTP = &tool.HTTPSpec{UserAgent: "passive-tool/1", Headers: map[string]string{"X-Tool": "1"}}
		return m
	}

	passive := compiled(tool.NetEgressProxy, "discover.subdomains@1", "asset:domain")
	s := send(t, passive, "discover.subdomains@1")
	if s.bounty != "" || strings.Contains(s.ua, "jdoe") {
		t.Fatalf("a passive source received the identification: %+v", s)
	}
	if s.ua != "passive-tool/1" || s.own != "1" {
		t.Fatalf("the tool's own settings were lost: %+v", s)
	}

	prober := compiled(tool.NetTargets, "probe.http@1", "asset:http_service")
	prober.Features = &tool.Features{HTTPIdentity: true}
	if s := send(t, prober, "probe.http@1"); s.ua != "jdoe-research" || s.bounty != "jdoe" {
		t.Fatalf("a target-reaching http tool lost the identification: %+v", s)
	}

	// An exec tool behind the egress proxy: the placeholders expand
	// without the identification.
	m := netManifest("-ua", "{{http.user_agent}}", "{{http.headers:-H}}", "{{target.value}}")
	m.Permissions = tool.Permissions{Network: tool.NetEgressProxy}
	m.HTTP = &tool.HTTPSpec{Headers: map[string]string{"Accept": "*/*"}}
	p, ierr, err := (&Host{}).prepare(context.Background(), m, identityTask(), RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	argv, ierr := expandArgv(m.Run.Argv, p)
	if ierr != nil {
		t.Fatal(ierr)
	}
	for _, a := range argv {
		if strings.Contains(a, "jdoe") || strings.Contains(a, "X-Bug-Bounty") {
			t.Fatalf("exec argv carries the identification: %q", argv)
		}
	}
	if !slices.Contains(argv, "Accept: */*") {
		t.Fatalf("the tool's own header was lost: %q", argv)
	}
}

// The organization's TLS rule still applies to a task that gets no
// identification: a passive tool that skips TLS verification is refused
// where the organization forbids it.
func TestOrgTLSRuleKeptWithoutIdentification(t *testing.T) {
	m := httpManifest
	m.Run = nil
	m.Permissions = tool.Permissions{Network: tool.NetEgressProxy}
	m.HTTP = &tool.HTTPSpec{TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	task := identityTask()
	no := false
	task.OrgHTTP.AllowInsecureTLS = &no
	if _, ierr, err := (&Host{}).prepare(context.Background(), m, task, RunOptions{}); err != nil || ierr == nil || ierr.Class != tool.RefusedByPolicy {
		t.Fatalf("want refused_by_policy, got %v %v", err, ierr)
	}
}
