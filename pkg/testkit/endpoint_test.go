package testkit_test

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

func crawler(produces ...string) tool.Tool {
	return tool.New(tool.Manifest{
		Name: "ep-crawler", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
		Consumes: []string{"http_service"}, Produces: produces,
		Permissions: tool.Permissions{Network: tool.NetNone},
	}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
		r := ctis.NewReport()
		r.Endpoints = []ctis.Endpoint{
			{Origin: "https://app.example.com", Method: "GET", Path: "/api/users/42", Kind: "api", Source: "crawl",
				Params: []ctis.EndpointParam{{Location: "query", Name: "page"}}},
			{Origin: "not a url", Method: "GET", Path: "relative"},
		}
		_ = ctx.Emit().Report(r)
		for _, t := range task.Targets {
			ctx.TargetDone(t)
		}
		return nil
	})
}

// A tool that declares endpoint emits CTIS 1.6 endpoints through the
// runtime's checks: a valid one is kept, an invalid one refused.
func TestEndpointsReachTheReport(t *testing.T) {
	task := tool.Task{Targets: []tool.Target{{Ref: "a", Type: "http_service", Value: "https://app.example.com"}}}
	res := testkit.Run(t, crawler(tool.KindEndpoint), task)
	if len(res.Report.Endpoints) != 1 || res.Report.Endpoints[0].Path != "/api/users/42" {
		t.Fatalf("endpoints %+v", res.Report.Endpoints)
	}
	if res.Stats.Invalid != 1 {
		t.Fatalf("the invalid endpoint was not refused: %+v", res.Stats)
	}
	// SECURITY: a tool that does not declare endpoint cannot emit one.
	res = testkit.Run(t, crawler("asset:discovered_url"), task)
	if len(res.Report.Endpoints) != 0 {
		t.Fatalf("an undeclared endpoint was kept: %+v", res.Report.Endpoints)
	}
}
