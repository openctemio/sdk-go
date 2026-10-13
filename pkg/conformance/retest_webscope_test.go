package conformance

import (
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

// retestWebTool is an adapter-profile tool that retests by fetching
// <target>/env (which redirects to /.env) and <target>/.git/config: through
// ctx.HTTP(), which keeps to the job's web scope, or with a plain client
// when $CONFORMANCE_IGNORE_SCOPE=1.
func retestWebTool() {
	m := tool.Manifest{Name: "fake-tool", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"http_service"}, Produces: []string{"finding:misconfiguration"},
		Permissions: tool.Permissions{Network: tool.NetTargets}, Features: &tool.Features{Retest: true, WebScope: true}}
	run := func(tool.Context, tool.Task, tool.NoConfig) error { return nil }
	adapter.Serve(tool.WithRetest(tool.New(m, run), func(ctx tool.RetestContext, task tool.Task) error {
		client := ctx.HTTP()
		if os.Getenv("CONFORMANCE_IGNORE_SCOPE") == "1" {
			client = &http.Client{Timeout: 5 * time.Second}
		}
		byRef := map[string]string{}
		for _, t := range task.Targets {
			byRef[t.Ref] = strings.TrimSuffix(t.Value, "/")
		}
		for _, it := range task.Retest {
			for _, p := range []string{"/env", "/.git/config"} {
				if resp, err := client.Get(byRef[it.Target] + p); err == nil {
					_ = resp.Body.Close()
				}
			}
			ctx.Verdict(it, tool.Unverifiable, "conformance fixture")
		}
		for _, t := range task.Targets {
			ctx.TargetDone(t)
		}
		return nil
	}))
}

const retestTool = `tier: T1
consumes: [http_service]
produces: [finding:misconfiguration]
permissions: {network: targets}
FEATURES
run: {argv: [EXE]}
`

// SECURITY (acceptance): a tool that retests and declares
// features.web_scope gets a web-scoped retest task and passes when it keeps
// to the scope; one that requests the denied path fails. A networked tool
// that retests without features.web_scope gets a lint warning.
func TestContractSuite_RetestWebScope(t *testing.T) {
	declared := fakeManifest(t, strings.Replace(retestTool, "FEATURES", "features: {retest: true, web_scope: true}", 1), nil)
	if r := runContract(declared, ContractOptions{Env: map[string]string{fakeToolEnv: "retest-web"}}); len(r.errs) > 0 {
		t.Fatalf("a retest that keeps to the scope: %v", r.errs)
	}
	r := runContract(declared, ContractOptions{Env: map[string]string{fakeToolEnv: "retest-web", "CONFORMANCE_IGNORE_SCOPE": "1"}})
	if !hasErr(r, "Retest/web_scope: the retest requested /.env") {
		t.Fatalf("a retest that ignores the scope passed: %v", r.errs)
	}
	m, err := tool.LoadManifestFile(fakeManifest(t, strings.Replace(retestTool, "FEATURES", "features: {retest: true}", 1), nil))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range LintDescriptor(m) {
		found = found || l.Path == "/features/web_scope"
	}
	if !found {
		t.Fatalf("no lint warning for a retest tool without features.web_scope: %v", LintDescriptor(m))
	}
}
