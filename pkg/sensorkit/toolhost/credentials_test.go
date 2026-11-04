package toolhost

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// credTool says which value of each declared source key it received, by a
// short prefix (the full value is redacted from everything it emits).
var credTool = tool.New(tool.Manifest{
	Name: "cred-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T0,
	Consumes: []string{"domain_name"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone, Credentials: []tool.CredentialReq{
		{Name: "alpha", Kind: "api_key"}, {Name: "beta", Kind: "api_key"}}},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	var got []string
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if k, err := ctx.Secret(name); err == nil {
			v := k.Reveal()
			ctx.Log().Info("key " + v)
			got = append(got, name+"="+v[:6])
		}
	}
	for _, t := range task.Targets {
		if err := ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", RuleID: "r1", Title: "got " + strings.Join(got, ","), Severity: "info"}); err != nil {
			return err
		}
		ctx.TargetDone(t)
	}
	return nil
})

func TestTaskCredentialsPrecedence(t *testing.T) {
	m := credTool.Manifest()
	local := map[string]string{"alpha": "local-a", "beta": "local-b"}
	fetchOf := func(set *core.ToolCredentialSet, err error) context.Context {
		return core.WithToolCredentials(context.Background(), func(_ context.Context, tool string) (*core.ToolCredentialSet, error) {
			if tool != m.Name {
				t.Fatalf("asked for tool %q", tool)
			}
			return set, err
		})
	}
	cases := []struct {
		name     string
		ctx      context.Context
		want     map[string]string
		wantLine bool
	}{
		{"not a platform job: the operator's", context.Background(), local, false},
		{"organization wins, operator fills on its own sensor",
			fetchOf(&core.ToolCredentialSet{Values: map[string]string{"alpha": "org-a"}, LocalFallback: true}, nil),
			map[string]string{"alpha": "org-a", "beta": "local-b"}, false},
		{"shared sensor: the organization's only",
			fetchOf(&core.ToolCredentialSet{Values: map[string]string{"alpha": "org-a"}}, nil),
			map[string]string{"alpha": "org-a"}, false},
		{"shared sensor, organization has none: nothing",
			fetchOf(&core.ToolCredentialSet{}, nil), map[string]string{}, false},
		{"older platform: the operator's",
			fetchOf(nil, core.ErrToolCredentialsUnsupported), local, false},
		{"platform failed: neither, and the log says so",
			fetchOf(nil, errors.New("v2 http 503")), nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, line := taskCredentials(c.ctx, m, local)
			if fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Fatalf("credentials %v, want %v", got, c.want)
			}
			if (line != nil) != c.wantLine {
				t.Fatalf("log line %+v", line)
			}
		})
	}
	// A tool that declares no credentials never asks the platform.
	asked := false
	ctx := core.WithToolCredentials(context.Background(), func(context.Context, string) (*core.ToolCredentialSet, error) {
		asked = true
		return nil, nil
	})
	if _, _ = taskCredentials(ctx, tool.Manifest{Name: "none"}, nil); asked {
		t.Fatal("a tool without credentials asked the platform")
	}
}

// End to end through the tool host: the organization's key reaches the
// tool for the declared name, the operator's fills the other only where
// allowed, each task asks once (nothing kept between tasks), and no value
// reaches the logs or the report.
func TestOrganizationCredentialsReachTheTask(t *testing.T) {
	var calls atomic.Int32
	fetch := func(fallback bool) context.Context {
		return core.WithToolCredentials(context.Background(), func(context.Context, string) (*core.ToolCredentialSet, error) {
			calls.Add(1)
			return &core.ToolCredentialSet{Values: map[string]string{"alpha": "org-aaa-secret-1", "gamma": "org-ggg-undeclared"}, LocalFallback: fallback}, nil
		})
	}
	local := map[string]string{"alpha": "loc-aaa-secret-2", "beta": "loc-bbb-secret-3"}
	run := func(ctx context.Context) *Outcome {
		t.Helper()
		out, err := testHost(t).RunBuiltin(ctx, credTool, tool.Task{Targets: oneTarget}, RunOptions{Credentials: local})
		if err != nil {
			t.Fatal(err)
		}
		if out.Status != tool.StatusOK || len(out.Report.Findings) != 1 {
			t.Fatalf("status %s err %v stderr %s", out.Status, out.Err, out.Stderr)
		}
		all := fmt.Sprintf("%+v %s %+v", out.Logs, out.Stderr, out.Report)
		for _, secret := range []string{"org-aaa-secret-1", "loc-aaa-secret-2", "loc-bbb-secret-3", "org-ggg-undeclared"} {
			if strings.Contains(all, secret) {
				t.Fatalf("%s reached the outcome: %s", secret, all)
			}
		}
		return out
	}
	if got := run(fetch(true)).Report.Findings[0].Title; got != "got alpha=org-aa,beta=loc-bb" {
		t.Fatalf("organization sensor: %q", got)
	}
	if got := run(fetch(false)).Report.Findings[0].Title; got != "got alpha=org-aa" {
		t.Fatalf("shared sensor: %q", got)
	}
	if calls.Load() != 2 {
		t.Fatalf("the platform was asked %d times for two tasks", calls.Load())
	}
}
