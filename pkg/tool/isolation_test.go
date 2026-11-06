package tool

import (
	"strings"
	"testing"
)

func TestManifestIsolation(t *testing.T) {
	cases := []struct {
		name, yaml, errPath string
		want                Isolation
	}{
		{"unset reads as process", baseYAML, "", IsolationProcess},
		{"process", patch(baseYAML, "tier", "tier: T0\nisolation: process"), "", IsolationProcess},
		{"strong", patch(baseYAML, "tier", "tier: T0\nisolation: strong"), "", IsolationStrong},
		{"unknown value", patch(baseYAML, "tier", "tier: T0\nisolation: maximum"), "/isolation", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m, err := LoadManifest([]byte(c.yaml))
			if c.errPath != "" {
				if err == nil || !strings.Contains(err.Error(), c.errPath) {
					t.Fatalf("want an error at %s, got %v", c.errPath, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := m.Isolation.Effective(); got != c.want {
				t.Fatalf("effective isolation %q, want %q", got, c.want)
			}
			if got := m.Contract().Isolation; c.want == IsolationStrong && got != "strong" {
				t.Fatalf("the contract the sensor reports says %q", got)
			}
		})
	}
}

// The isolation a tool asks for is part of its digest (a signed statement); an unset one adds no key.
func TestIsolationIsPartOfTheDigest(t *testing.T) {
	a, err := LoadManifest([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadManifest([]byte(patch(baseYAML, "tier", "tier: T0\nisolation: process")))
	if err != nil {
		t.Fatal(err)
	}
	if a.Digest() == b.Digest() {
		t.Fatal("an explicit isolation must be part of the digest")
	}
	c, _ := LoadManifest([]byte(patch(baseYAML, "tier", "tier: T0\nisolation: strong")))
	if a.Digest() == c.Digest() {
		t.Fatal("the digest must change with the isolation a tool asks for")
	}
}
