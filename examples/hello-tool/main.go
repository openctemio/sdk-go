// Example: a complete third-party tool in one file (docs/tool-quickstart.md).
//
// The tool implements the two-method contract (tool.Tool: Manifest and Run)
// through tool.New, which builds it from tool.yaml and a typed run function.
// The sensor starts the program as its own sandboxed process and speaks the
// adapter protocol with it; adapter.Serve is the whole of that on this side.
//
//	go build -o bin/hello-tool ./examples/hello-tool
//	openctem tool test examples/hello-tool
package main

import (
	_ "embed"
	"net/http"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

//go:embed tool.yaml
var manifest []byte

// ruleID names the check in every finding; fingerprints and suppressions key
// on it, so keep it stable across versions.
const ruleID = "hello-tool/xcto-missing"

// config is the tool's typed configuration. The descriptor's config schema
// is the contract; the runtime validates a task's config against it before
// Run, and a key the schema does not list never reaches the tool.
type config struct {
	Rate int `json:"rate"`
}

func main() {
	adapter.Serve(newTool())
}

func newTool() tool.Tool {
	m, err := tool.LoadManifest(manifest)
	if err != nil {
		panic(err)
	}
	return tool.New(m, run)
}

// run does one task: one request per target. The runtime already admitted
// the targets against the signed scope and the sensor's local policy.
func run(ctx tool.Context, task tool.Task, _ config) error {
	for _, t := range task.Targets {
		if err := ctx.Err(); err != nil {
			return err // the runtime cancelled the task
		}
		u := t.URL("")
		if u == "" {
			ctx.TargetSkipped(t, "not a URL or host")
			continue
		}
		// ctx.HTTP() is the only way out: it goes through the task's egress
		// forwarder, which reaches the task's targets and nothing else.
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			ctx.TargetError(t, tool.Invalid("%v", err))
			continue
		}
		resp, err := ctx.HTTP().Do(req)
		if err != nil {
			ctx.TargetError(t, tool.Unreachable(err))
			continue
		}
		_ = resp.Body.Close()
		if resp.Header.Get("X-Content-Type-Options") == "" {
			err := ctx.Emit().Finding(t, ctis.Finding{
				Type:     ctis.FindingTypeMisconfiguration,
				RuleID:   ruleID,
				Title:    "X-Content-Type-Options header missing",
				Severity: ctis.SeverityLow,
				Web:      &ctis.WebLocation{URL: u, Method: http.MethodGet},
			})
			if err != nil {
				return err // the runtime refused the record: fix the tool
			}
		}
		ctx.TargetDone(t)
	}
	return nil
}
