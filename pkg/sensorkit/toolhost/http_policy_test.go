package toolhost

import (
	"context"
	"slices"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// httpPolicy is a fake local policy with schema v3's http section.
type httpPolicy struct {
	fakePolicy
	ua            string
	allowInsecure bool
}

func (p *httpPolicy) HTTPPolicy() (string, bool) { return p.ua, p.allowInsecure }

var httpManifest = tool.Manifest{
	APIVersion: tool.APIVersion, Name: "acme-cli", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
	Consumes: []string{"repository"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone},
	Run:         &tool.RunSpec{Profile: tool.ProfileExec, Argv: []string{"acme", "{{http.user_agent}}"}, Output: &tool.OutputSpec{Format: tool.OutputCTIS, From: "stdout"}},
}

var httpTask = tool.Task{Targets: []tool.Target{{Ref: "r", Type: "repository", Value: "x"}}}

// The sensor's local policy (schema v3) wins over the tool: its
// User-Agent replaces the tool's, in the task the tool receives and in
// exec argv.
func TestLocalPolicyForcesTheUserAgent(t *testing.T) {
	m := httpManifest
	m.HTTP = &tool.HTTPSpec{UserAgent: "acme-cli/1.0", Headers: map[string]string{"X-Scan": "1"}}
	h := &Host{Policy: &httpPolicy{ua: "corp-security-scan", allowInsecure: true}}
	p, ierr, err := h.prepare(context.Background(), m, httpTask, RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	if p.task.HTTP == nil || p.task.HTTP.UserAgent != "corp-security-scan" || p.task.HTTP.Headers["X-Scan"] != "1" {
		t.Fatalf("effective http %+v", p.task.HTTP)
	}
	if m.HTTP.UserAgent != "acme-cli/1.0" {
		t.Fatal("the manifest was changed in place")
	}
	argv, ierr := expandArgv(m.Run.Argv, p)
	if ierr != nil || !slices.Equal(argv, []string{"acme", "corp-security-scan"}) {
		t.Fatalf("argv %q %v", argv, ierr)
	}
}

// SECURITY: a tool that skips TLS verification is refused where the
// local policy forbids it; a job cannot set the task's http settings.
func TestLocalPolicyForbidsInsecureTLS(t *testing.T) {
	m := httpManifest
	m.HTTP = &tool.HTTPSpec{TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	h := &Host{Policy: &httpPolicy{allowInsecure: false}}
	if _, ierr, err := h.prepare(context.Background(), m, httpTask, RunOptions{}); err != nil || ierr == nil || ierr.Class != tool.RefusedByPolicy {
		t.Fatalf("insecure TLS under a forbidding policy: %v %v", err, ierr)
	}

	task := httpTask
	task.HTTP = &tool.HTTPSpec{UserAgent: "from-the-job", TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	p, ierr, err := (&Host{}).prepare(context.Background(), httpManifest, task, RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	if p.task.HTTP != nil {
		t.Fatalf("a job set the task's http settings: %+v", p.task.HTTP)
	}
}
