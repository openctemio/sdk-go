package tool

import "testing"

func TestQueryArgs(t *testing.T) {
	if f, ok := QueryArgs("http.query:--param"); !ok || f != "--param" {
		t.Fatal(f, ok)
	}
	for _, bad := range []string{"http.query", "http.query:", "http.query:x", "http.query:-a b", "http.headers:-H"} {
		if _, ok := QueryArgs(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestQueryPlaceholderIsValidAsAWholeArgumentOnly(t *testing.T) {
	m := Manifest{APIVersion: APIVersion, Name: "qtool", Version: "1.0.0", Class: TargetScan, Tier: T0,
		Consumes: []string{"domain"}, Produces: []string{"finding:misconfiguration"}, Permissions: Permissions{Network: NetTargets},
		Features: &Features{HTTPQuery: true},
		Run:      &RunSpec{Profile: ProfileExec, Argv: []string{"qtool", "{{http.query:--param}}"}, Output: &OutputSpec{Format: OutputCTIS, From: "stdout"}}}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	m.Run.Argv = []string{"qtool", "--p={{http.query:--param}}"}
	if err := m.Validate(); err == nil {
		t.Fatal("a query placeholder inside an argument must be refused")
	}
}
