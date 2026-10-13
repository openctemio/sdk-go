package toolhost

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
	"github.com/openctemio/sdk-go/pkg/webscope"
)

// A task's web scope reaches its forwarder, with the task's target hosts
// as the scope's default hosts; a task without one gets none.
func TestTaskScopeCarriesWebScope(t *testing.T) {
	h := &Host{}
	m := tool.Manifest{Permissions: tool.Permissions{Network: tool.NetTargets}}
	ws := &webscope.Scope{DenyPaths: []string{"/admin"}}
	s := h.taskScope(context.Background(), m, tool.Task{WebScope: ws,
		Targets: []tool.Target{{Value: "https://localhost:8443/x"}, {Value: "192.0.2.5"}}})
	if s.Web != ws || len(s.WebTargets) != 2 || s.WebTargets[0] != "localhost" || s.WebTargets[1] != "192.0.2.5" {
		t.Fatalf("scope %+v", s)
	}
	if s = h.taskScope(context.Background(), m, tool.Task{Targets: []tool.Target{{Value: "192.0.2.5"}}}); s.Web != nil || s.WebTargets != nil {
		t.Fatalf("scope without a web scope %+v", s)
	}
}
