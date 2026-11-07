package core

import (
	"fmt"
	"strings"
	"testing"
)

// The owner's rotation list: read, reported by length, exclusive with
// http.user_agent, validated like the platform's (no line break, at most
// 200 values, none twice); a bad list stops the policy from loading.
func TestLocalPolicyUserAgents(t *testing.T) {
	lp := mustPolicy(t, "apiVersion: openctem.io/sensor-policy/v1\nhttp:\n  user_agents: [\"a/1\", \"b/2\", \"c/3\"]\n")
	if got := lp.HTTPUserAgents(); len(got) != 3 || got[1] != "b/2" {
		t.Fatalf("HTTPUserAgents = %v", got)
	}
	if n := lp.Report().Summary.HTTPUserAgents; n != 3 {
		t.Fatalf("summary: %d", n)
	}
	var many []string
	for i := range 201 {
		many = append(many, fmt.Sprintf("\"ua/%d\"", i))
	}
	for name, doc := range map[string]string{
		"both":      "http:\n  user_agent: one\n  user_agents: [\"a/1\"]\n",
		"line feed": "http:\n  user_agents: [\"a/1\\r\\nX-Injected: 1\"]\n",
		"duplicate": "http:\n  user_agents: [\"a/1\", \"a/1\"]\n",
		"201":       "http:\n  user_agents: [" + strings.Join(many, ", ") + "]\n",
	} {
		if _, err := ParseLocalPolicy([]byte("apiVersion: openctem.io/sensor-policy/v1\n"+doc), LocalPolicyOptions{}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var none *LocalPolicy
	if none.HTTPUserAgents() != nil {
		t.Fatal("no policy: a list")
	}
}
