// toyweb is a toy dast.web@1 tool on sdk-go: it reports web origins that do
// not send the security response headers a scan asks for.
package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/tool/adapter"
)

//go:embed tool.yaml
var manifestYAML []byte

type config struct {
	Headers        []string `json:"require_headers"`
	RequestTimeout int      `json:"request_timeout"`
	MaxMinutes     int      `json:"max_minutes"`
}

func main() {
	m, err := tool.LoadManifest(manifestYAML)
	if err != nil {
		panic(err)
	}
	m.Config = nil // New derives nothing: keep the file's schema
	m2, _ := tool.LoadManifest(manifestYAML)
	m.Config = m2.Config
	adapter.Serve(tool.New(m, run))
}

func run(ctx tool.Context, task tool.Task, cfg config) error {
	headers := cfg.Headers
	if len(headers) == 0 {
		headers = []string{"content-security-policy", "x-frame-options"}
	}
	timeout := time.Duration(cfg.RequestTimeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := ctx.HTTP()
	client.Timeout = timeout
	for _, t := range task.Targets {
		url := t.URL("/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			ctx.TargetError(t, err)
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			ctx.TargetError(t, err)
			continue
		}
		_ = resp.Body.Close()
		assetRef := ""
		if t.Type == "" {
			// The task names the target only by its value: file the
			// findings on an asset of that value.
			assetRef = "t-" + t.Ref
			if err := ctx.Emit().Asset(ctis.Asset{ID: assetRef, Type: ctis.AssetTypeHTTPService, Value: url, Name: url}); err != nil {
				return err
			}
		}
		for _, h := range headers {
			if resp.Header.Get(h) != "" {
				continue
			}
			f := ctis.Finding{
				Type:        ctis.FindingTypeMisconfiguration,
				RuleID:      "toyweb.missing-" + h,
				Title:       fmt.Sprintf("Response header %s is missing", h),
				Description: fmt.Sprintf("%s answered without the %s header.", url, h),
				Severity:    ctis.SeverityLow,
				Web:         &ctis.WebLocation{URL: url, Method: http.MethodGet},
				AssetRef:    assetRef,
			}
			if err := ctx.Emit().Finding(t, f); err != nil {
				return err
			}
		}
		ctx.TargetDone(t)
	}
	return nil
}
