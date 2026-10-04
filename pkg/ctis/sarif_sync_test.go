package ctis

import (
	"testing"
)

const sarifSyncRepo = `"versionControlProvenance":[{"repositoryUri":"https://github.com/example/shop"}],`

// A result without its own level inherits the rule's defaultConfiguration
// level (SARIF spec) instead of collapsing to medium.
func TestFromSARIF_RuleLevelSeverityFallback(t *testing.T) {
	sarif := []byte(`{"version":"2.1.0","runs":[{` + sarifSyncRepo + `
	  "tool":{"driver":{"name":"demo","rules":[
	    {"id":"RULE-ERR","defaultConfiguration":{"level":"error"}},
	    {"id":"RULE-NOTE","defaultConfiguration":{"level":"note"}}]}},
	  "results":[
	    {"ruleId":"RULE-ERR","message":{"text":"rule error"}},
	    {"ruleId":"RULE-NOTE","message":{"text":"rule note"}},
	    {"ruleId":"RULE-ERR","level":"warning","message":{"text":"result level wins"}}]}]}`)
	r, err := FromSARIF(sarif, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []Severity{SeverityHigh, SeverityLow, SeverityMedium}
	for i, w := range want {
		if r.Findings[i].Severity != w {
			t.Errorf("finding %d: severity %s, want %s", i, r.Findings[i].Severity, w)
		}
	}
}

// The same log converts to the same fingerprint every time.
func TestFromSARIF_FingerprintDeterministic(t *testing.T) {
	sarif := []byte(`{"version":"2.1.0","runs":[{` + sarifSyncRepo + `
	  "tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","message":{"text":"m"},
	  "fingerprints":{"c/v1":"cccccccccccccccc","a/v1":"aaaaaaaaaaaaaaaa","b/v1":"bbbbbbbbbbbbbbbb","d/v1":"dddddddddddddddd"}}]}]}`)
	seen := map[string]int{}
	for i := 0; i < 200; i++ {
		r, err := FromSARIF(sarif, nil)
		if err != nil {
			t.Fatal(err)
		}
		seen[r.Findings[0].Fingerprint]++
	}
	if len(seen) != 1 || seen["aaaaaaaaaaaaaaaa"] != 200 {
		t.Fatalf("fingerprints over 200 conversions: %v, want the lowest key every time", seen)
	}
}

func TestAllDataFlowLocationTypes(t *testing.T) {
	if len(AllDataFlowLocationTypes()) != 5 {
		t.Error("five data flow location types")
	}
}
