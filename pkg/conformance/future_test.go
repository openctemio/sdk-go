package conformance

import (
	"io"
	"net/http"
	"strings"
	"testing"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// FutureFields puts a member no SDK knows into the platform's answers, and
// the SDK client still reads them: hello, heartbeat and the command poll.
func TestFutureFields_AnswersCarryAnUnknownMemberTheClientIgnores(t *testing.T) {
	f := NewFakePlatform(true)
	f.SetControl(true)
	f.SetFutureFields(true)
	t.Cleanup(f.Close)
	f.QueueCommand("0192a3b4-0000-7000-8000-00000000f001")

	req, _ := http.NewRequest(http.MethodGet, f.URL()+protov2.PathPrefix+protov2.HelloPath, nil)
	req.Header.Set("Authorization", "Bearer "+f.APIKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), FutureMember) {
		t.Fatalf("hello does not carry %s: %s", FutureMember, body)
	}

	c := newClient(t, f, "")
	h, err := c.Hello(t.Context())
	if err != nil || !h.Supports(protov2.FeatureHeartbeat) {
		t.Fatalf("Hello = %+v, %v", h, err)
	}
	cmds, err := c.GetCommands(t.Context())
	if err != nil || len(cmds.Commands) != 1 {
		t.Fatalf("GetCommands = %+v, %v", cmds, err)
	}
}
