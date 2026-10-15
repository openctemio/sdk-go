package toolhost

import (
	"context"
	"slices"
	"testing"

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
