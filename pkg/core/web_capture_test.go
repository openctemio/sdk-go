package core

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLiveHostWebContentPassthrough(t *testing.T) {
	at := time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC)
	in := LiveHost{URL: "https://a.example.com/", WebContent: []WebCapture{{
		URL: "https://a.example.com/", StatusCode: 200, Size: 3, SHA256: strings.Repeat("a", 64), Body: "abc", FetchedAt: at,
	}}}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out LiveHost
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.WebContent) != 1 || out.WebContent[0] != in.WebContent[0] {
		t.Fatalf("round trip = %#v", out.WebContent)
	}
	// Without captures the member is absent, so existing reports are unchanged.
	raw, _ = json.Marshal(LiveHost{URL: "https://a.example.com/"})
	if strings.Contains(string(raw), "web_content") {
		t.Fatalf("empty WebContent marshaled: %s", raw)
	}
}
