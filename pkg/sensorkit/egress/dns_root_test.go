package egress

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A query for the root name (a resolver library probing ".") is refused as
// before, and the record and its reason name it "." instead of an empty host.
func TestRootDNSQueryIsRefusedAndNamed(t *testing.T) {
	tests := []struct {
		name, query, host string
	}{
		{"root", ".", "."},
		{"unknown name", "other.example.", "other.example"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := New(Scope{}, Limits{})
			if m := askDNS(t, f, tc.query); m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
				t.Fatalf("%+v, want a refusal", m.Header)
			}
			r := f.Refusals()
			if len(r) != 1 {
				t.Fatalf("records: %+v", r)
			}
			if r[0].Host != tc.host || r[0].Protocol != "dns" {
				t.Fatalf("record: %+v", r[0])
			}
			if !strings.Contains(r[0].Reason, ": "+tc.host+" is not a target") {
				t.Fatalf("reason %q", r[0].Reason)
			}
		})
	}
}
