package toolhost

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func ptr[T any](v T) *T { return &v }

// The organization's HTTP policy (from the job) narrows after the local
// policy: its User-Agent applies unless the local policy forces one, and a
// tool that skips TLS verification is refused when either forbids it. The
// task the tool receives carries the result, never the policy itself.
func TestOrgHTTPPolicyNarrowsAfterTheLocalPolicy(t *testing.T) {
	ctx := context.Background()
	m := httpManifest
	m.HTTP = &tool.HTTPSpec{UserAgent: "acme-cli/1.0"}

	task := httpTask
	task.OrgHTTP = &core.OrgHTTPPolicy{UserAgent: "org-scan"}
	p, ierr, err := (&Host{}).prepare(ctx, m, task, RunOptions{})
	if err != nil || ierr != nil {
		t.Fatal(err, ierr)
	}
	if p.task.HTTP.UserAgent != "org-scan" || p.task.OrgHTTP != nil {
		t.Fatalf("organization user agent: %+v %+v", p.task.HTTP, p.task.OrgHTTP)
	}

	// The local policy's User-Agent wins over the organization's.
	p, ierr, err = (&Host{Policy: &httpPolicy{ua: "local-scan", allowInsecure: true}}).prepare(ctx, m, task, RunOptions{})
	if err != nil || ierr != nil || p.task.HTTP.UserAgent != "local-scan" {
		t.Fatalf("local wins: %+v %v %v", p, err, ierr)
	}

	// SECURITY: the organization forbids skipping TLS verification even
	// where the local policy allows it; it cannot allow what the local
	// policy forbids.
	insecure := httpManifest
	insecure.HTTP = &tool.HTTPSpec{TLS: &tool.TLSSpec{InsecureSkipVerify: true}}
	forbid := httpTask
	forbid.OrgHTTP = &core.OrgHTTPPolicy{AllowInsecureTLS: ptr(false)}
	if _, ierr, _ := (&Host{Policy: &httpPolicy{allowInsecure: true}}).prepare(ctx, insecure, forbid, RunOptions{}); ierr == nil || ierr.Class != tool.RefusedByPolicy {
		t.Fatalf("organization forbids insecure TLS: %v", ierr)
	}
	allow := httpTask
	allow.OrgHTTP = &core.OrgHTTPPolicy{AllowInsecureTLS: ptr(true)}
	if _, ierr, _ := (&Host{Policy: &httpPolicy{allowInsecure: false}}).prepare(ctx, insecure, allow, RunOptions{}); ierr == nil || ierr.Class != tool.RefusedByPolicy {
		t.Fatalf("the organization widened the local policy: %v", ierr)
	}
	if _, ierr, _ := (&Host{}).prepare(ctx, insecure, allow, RunOptions{}); ierr != nil {
		t.Fatalf("both allow: %v", ierr)
	}
}
