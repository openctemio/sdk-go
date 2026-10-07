package sensorkit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/sensorkit/toolhost"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// SECURITY: credentials a tool prints about its targets are masked in the
// text of every line before it leaves the sensor.
func TestRedactLogText(t *testing.T) {
	cases := map[string]string{
		"GET / with Authorization: Bearer eyJabc.def":  "Authorization: " + tool.Redacted,
		"header cookie: sid=abc123; theme=dark":        "cookie: " + tool.Redacted,
		"Set-Cookie: sid=zzz; HttpOnly":                "Set-Cookie: " + tool.Redacted,
		"fetching https://admin:hunter2@app.example/x": "https://" + tool.Redacted + "@app.example/x",
		"login with password=hunter2 user=bob":         "password=" + tool.Redacted + " user=bob",
		`{"api_key": "sk-live-1"}`:                     tool.Redacted,
		"url https://a.example/?token=abc123&page=2":   "token=" + tool.Redacted + "&page=2",
		"client_secret: s3cr3t":                        "client_secret: " + tool.Redacted,
	}
	for in, want := range cases {
		got := redactLogText(in)
		if !strings.Contains(got, want) {
			t.Errorf("%q -> %q, want it to contain %q", in, got, want)
		}
		for _, secret := range []string{"eyJabc", "abc123", "zzz", "hunter2", "sk-live-1", "s3cr3t"} {
			if strings.Contains(in, secret) && strings.Contains(got, secret) {
				t.Errorf("%q -> %q still holds %q", in, got, secret)
			}
		}
	}
	// Ordinary text is untouched.
	for _, keep := range []string{"template token-detect matched", "password reset page found at /reset", "found 3 open ports"} {
		if got := redactLogText(keep); got != keep {
			t.Errorf("%q changed to %q", keep, got)
		}
	}
}

// A tool host the sensor builds itself (as the sensor does for every
// scanner) ships its tools' lines to the platform through ToolLogSink.
func TestKit_ToolLogSinkForAnOwnHost(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	f.SetControl(true)
	f.SetLogs(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	// Taken before Run, like a sensor that configures its host at start.
	own := &toolhost.Host{Sensor: "own", RuntimeName: "own-host", LogSink: k.ToolLogSink()}
	k.HandleCommand("own_scan", commandExecFunc(func(ctx context.Context, cmd *core.Command) (*core.CommandExecutionResult, error) {
		task := tool.Task{ID: cmd.ID, Targets: []tool.Target{{Ref: "t1", Type: "ip_address", Value: "1.1.1.1"}}}
		if _, err := own.RunBuiltin(ctx, loggingTool, task, toolhost.RunOptions{}); err != nil {
			return nil, err
		}
		return &core.CommandExecutionResult{}, nil
	}))
	id := "0192a3b4-0000-7000-8000-0000000000f9"
	f.QueueCommandPayload(id, "own_scan", json.RawMessage(`{}`))
	stop := runKit(t, k)
	waitCompleted(t, f, id, out, errw)
	if err := stop(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	var toolLines int
	for _, l := range f.CommandLogs(id) {
		if l.Source == "kit-logging" {
			toolLines++
		}
	}
	if toolLines == 0 {
		t.Fatalf("no line of the own host's tool reached the platform: %+v\nstderr:%s", f.CommandLogs(id), errw.String())
	}
}
