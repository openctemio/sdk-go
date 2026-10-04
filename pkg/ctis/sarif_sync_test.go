package ctis

import (
	"math"
	"strconv"
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
	if got := sarifFingerprint(map[string]string{"k": string(make([]byte, 65))}); len(got) != 64 {
		t.Errorf("long fingerprint must be hashed, got %q", got)
	}
	if sarifFingerprint(nil) != "" || sarifFingerprint(map[string]string{"k": ""}) != "" {
		t.Error("no usable fingerprint must give empty")
	}
}

func TestItoaMinInt(t *testing.T) {
	for _, n := range []int{0, 42, -42, math.MaxInt, math.MinInt} {
		if got, want := itoa(n), strconv.Itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestAllDataFlowLocationTypes(t *testing.T) {
	if len(AllDataFlowLocationTypes()) != 5 {
		t.Error("five data flow location types")
	}
}

// partialFingerprints reach the finding (SARIF 2.1.0 section 3.27.17): a
// receiver keys a line-independent identity on primaryLocationLineHash.
func TestFromSARIF_PartialFingerprintsPassThrough(t *testing.T) {
	sarif := []byte(`{"version":"2.1.0","runs":[{` + sarifSyncRepo + `
	  "tool":{"driver":{"name":"CodeQL"}},"results":[
	    {"ruleId":"js/sql-injection","message":{"text":"m"},
	     "partialFingerprints":{"primaryLocationLineHash":"39fa2ee980eb94b0:1","empty":""}},
	    {"ruleId":"js/xss","message":{"text":"m"}}]}]}`)
	r, err := FromSARIF(sarif, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := r.Findings[0].PartialFingerprints
	if got["primaryLocationLineHash"] != "39fa2ee980eb94b0:1" {
		t.Fatalf("partial fingerprints = %v, want primaryLocationLineHash kept", got)
	}
	if _, ok := got["empty"]; ok {
		t.Fatal("an empty partial fingerprint was kept")
	}
	if r.Findings[1].PartialFingerprints != nil {
		t.Fatalf("a result without partial fingerprints got %v", r.Findings[1].PartialFingerprints)
	}
}
