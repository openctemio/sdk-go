package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

var probe = tool.New(tool.Manifest{
	Name: "probe", Version: "1.0.0", Class: tool.TargetScan, Tier: tool.T1,
	Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"},
	Permissions: tool.Permissions{Network: tool.NetNone},
}, func(ctx tool.Context, task tool.Task, _ tool.NoConfig) error {
	for _, t := range task.Targets {
		_ = ctx.Emit().Finding(t, ctis.Finding{Type: "misconfiguration", Title: "x", Severity: "low"})
		_ = ctx.Emit().Asset(ctis.Asset{Type: "ip_address", Value: "10.0.0.1"}) // undeclared
		ctx.TargetDone(t)
	}
	return nil
})

func serve(t *testing.T, in string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	if err := ServeIO(context.Background(), probe, strings.NewReader(in), &out); err != nil && !strings.Contains(in, `"protocol":[9]`) {
		t.Fatalf("serve: %v", err)
	}
	var msgs []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("stdout is not protocol only: %q", l)
		}
		msgs = append(msgs, m)
	}
	return msgs
}

func TestServeProtocol(t *testing.T) {
	in := `{"v":1,"type":"hello","protocol":[1]}
{"v":1,"type":"something_new"}
{"v":1,"type":"describe"}
{"v":1,"type":"validate","task":{"id":"t","config":{"x":1}}}
{"v":1,"type":"run","task":{"id":"t","targets":[{"ref":"a","type":"domain","value":"a.example"}],"workdir":"/tmp"}}
`
	msgs := serve(t, in)
	types := []string{}
	for _, m := range msgs {
		types = append(types, m["type"].(string))
	}
	got := strings.Join(types, ",")
	if got != "hello,manifest,validation,record,record,target_status,result" {
		t.Fatalf("messages %s", got)
	}
	if msgs[2]["ok"] != false {
		t.Fatalf("config given to a tool without config validated: %v", msgs[2])
	}
	// The undeclared record still goes to the runtime, which quarantines it
	// and decides the outcome.
	if msgs[6]["status"] != "ok" || msgs[4]["kind"] != "asset" {
		t.Fatalf("result %v, records %v", msgs[6], msgs[4])
	}
}

func TestServeRefusesUnknownProtocol(t *testing.T) {
	var out bytes.Buffer
	err := ServeIO(context.Background(), probe, strings.NewReader(`{"v":1,"type":"hello","protocol":[9]}`+"\n"), &out)
	if err == nil || out.Len() != 0 {
		t.Fatalf("err %v out %q", err, out.String())
	}
	if err := ServeIO(context.Background(), probe, strings.NewReader(`{"v":1,"type":"run"}`+"\n"), &out); err == nil {
		t.Fatal("a run before hello must be refused")
	}
}
