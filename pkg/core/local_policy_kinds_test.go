package core

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// SECURITY (research/468 D7): the report says whether the policy can admit
// a public and a private target, as two booleans; the ranges never leave
// the host.
func TestLocalPolicyReportTargetKinds(t *testing.T) {
	const (
		ranges = "10.0.0.0/8,192.0.2.0/24"
		secret = "10.20.30.0/24"
	)
	for _, tc := range []struct {
		name           string
		opts           LocalPolicyOptions
		envPrivate     string
		public, privat bool
	}{
		{"absent, no private consent", LocalPolicyOptions{}, "", true, false},
		{"absent, private consent", LocalPolicyOptions{}, "1", true, true},
		{"absent and required", LocalPolicyOptions{Required: true}, "1", false, false},
		{"env 10/8 only", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "10.0.0.0/8", EnvSensorAllowPrivateTargets: "1"})}, "1", false, true},
		{"env 10/8 and a host inside it", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "10.0.0.0/8," + secret, EnvSensorAllowPrivateTargets: "1"})}, "1", false, true},
		{"env public only", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "198.51.100.0/24"})}, "", true, false},
		{"env public and private", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: ranges, EnvSensorAllowPrivateTargets: "1"})}, "1", true, true},
		{"env a range wider than 10/8", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "8.0.0.0/5", EnvSensorAllowPrivateTargets: "1"})}, "1", true, true},
		{"env ULA only", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "fd00::/8", EnvSensorAllowPrivateTargets: "1"})}, "1", false, true},
		{"env a domain", LocalPolicyOptions{LookupEnv: env(map[string]string{EnvAllowedRanges: "*.example.com"})}, "", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvSensorAllowPrivateTargets, tc.envPrivate)
			opts := tc.opts
			opts.DefaultPath = filepath.Join(t.TempDir(), "none.yaml")
			if opts.LookupEnv == nil {
				opts.LookupEnv = env(map[string]string{EnvSensorAllowPrivateTargets: tc.envPrivate})
			}
			lp, err := LoadLocalPolicy(opts)
			if err != nil {
				t.Fatal(err)
			}
			r := lp.Report()
			if r.AllowsPublic != tc.public || r.AllowsPrivate != tc.privat {
				t.Fatalf("allows_public %t allows_private %t, want %t %t", r.AllowsPublic, r.AllowsPrivate, tc.public, tc.privat)
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			for _, leak := range []string{"10.0.0.0", secret, "192.0.2.0", "198.51.100", "fd00", "example.com", "8.0.0.0"} {
				if strings.Contains(string(b), leak) {
					t.Fatalf("the report carries a range or a name (%s): %s", leak, b)
				}
			}
			if !strings.Contains(string(b), `"allows_public":`) || !strings.Contains(string(b), `"allows_private":`) {
				t.Fatalf("the booleans must always be sent: %s", b)
			}
		})
	}
}

// A policy file: an allow list of private ranges only refuses public
// targets; without the private switch it admits no private target either;
// no allow list follows the platform.
func TestLocalPolicyFileTargetKinds(t *testing.T) {
	for _, tc := range []struct {
		name, doc      string
		lookup         func(string) (string, bool)
		public, privat bool
	}{
		{"private allow list", "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow_private: true\n  allow: [\"10.0.0.0/8\", \"172.16.0.0/12\"]\n", privateOn, false, true},
		{"public allow list", "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow: [\"203.0.113.0/24\"]\n", privateOn, true, false},
		{"no allow list, private off", "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  deny: [\"203.0.113.7\"]\n", env(nil), true, false},
		{"allow all", "apiVersion: openctem.io/sensor-policy/v1\ntargets:\n  allow_private: true\n  allow: [\"*\"]\n", privateOn, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writePolicy(t, t.TempDir(), tc.doc, 0o644)
			lp, err := LoadLocalPolicy(LocalPolicyOptions{Path: p, LookupEnv: tc.lookup})
			if err != nil {
				t.Fatal(err)
			}
			if r := lp.Report(); r.AllowsPublic != tc.public || r.AllowsPrivate != tc.privat {
				t.Fatalf("allows_public %t allows_private %t, want %t %t", r.AllowsPublic, r.AllowsPrivate, tc.public, tc.privat)
			}
		})
	}
}
