package toolrt

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// Per-request results reach the verdict, bounded and cleaned: the tool's
// output is hostile until checked.
func TestVerdictKeepsCleanRequests(t *testing.T) {
	a := retestAsm(t)
	reqs := []tool.RequestResult{
		{URL: "https://a.example/swagger-ui/index.html", Status: 200, Matched: true},
		{URL: "https://a.example/docs\nX: y", Status: 404, EdgeVendor: "cloudflare", EdgeState: "challenged"},
		{URL: "", Status: 200},
		{URL: "https://a.example/x", Status: 70000, EdgeVendor: "Not A Token!"},
	}
	_ = a.Verdict("i0", tool.VerdictReport{Verdict: tool.StillPresent, Requests: reqs})
	_ = a.Target("t0", tool.StateDone, nil)
	_ = a.Target("t1", tool.StateDone, nil)
	got := a.Verdicts(nil)[0].Requests
	if len(got) != 3 {
		t.Fatalf("want 3 requests (the URL-less one dropped), got %+v", got)
	}
	if !got[0].Matched || got[0].Status != 200 {
		t.Errorf("first: %+v", got[0])
	}
	if strings.ContainsAny(got[1].URL, "\n\r") || got[1].EdgeVendor != "cloudflare" || got[1].EdgeState != "challenged" {
		t.Errorf("second: %+v", got[1])
	}
	if got[2].Status != 0 || got[2].EdgeVendor != "" {
		t.Errorf("third: %+v", got[2])
	}
}

func TestVerdictRequestsAreBounded(t *testing.T) {
	a := retestAsm(t)
	var reqs []tool.RequestResult
	for i := 0; i < tool.MaxVerdictRequests+20; i++ {
		reqs = append(reqs, tool.RequestResult{URL: "https://a.example/p", Status: 200})
	}
	_ = a.Verdict("i0", tool.VerdictReport{Verdict: tool.StillPresent, Requests: reqs})
	_ = a.Target("t0", tool.StateDone, nil)
	_ = a.Target("t1", tool.StateDone, nil)
	if n := len(a.Verdicts(nil)[0].Requests); n != tool.MaxVerdictRequests {
		t.Fatalf("got %d, want %d", n, tool.MaxVerdictRequests)
	}
}
