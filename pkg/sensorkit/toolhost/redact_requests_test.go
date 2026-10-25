package toolhost

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// An out-of-process tool's request lines lose the task's secrets, as its
// verdict detail does.
func TestRedactRequestsRemovesSecrets(t *testing.T) {
	p := &prepared{secrets: []string{"hunter2-token"}}
	in := []tool.RequestResult{{URL: "https://a.example/hunter2-token/x", Error: "auth hunter2-token refused"}}
	got := p.redactRequests(in)
	if strings.Contains(got[0].URL, "hunter2-token") || strings.Contains(got[0].Error, "hunter2-token") {
		t.Fatalf("secret kept: %+v", got[0])
	}
	if !strings.Contains(in[0].URL, "hunter2-token") {
		t.Fatal("input mutated")
	}
}
