package jobsig

import (
	"context"
	"testing"
)

// SECURITY: a feed relay statement belongs to the platform (nil tenant id)
// and runs only on a shared sensor; the platform tenant id never passes on
// another kind of job, and a feed relay never names an organization.
func TestVerify_FeedRelayTenantRules(t *testing.T) {
	relay := func(st *Statement, b *Binding) {
		st.SensorScope, st.TenantID, st.CommandType, st.Tool, st.Targets = SensorScopeInstance, PlatformTenantID, CommandTypeFeedRelay, "", []string{"https://feeds.example/x"}
		b.Shared, b.TenantID, b.CommandType = true, "", CommandTypeFeedRelay
		b.Payload = []byte(`{"targets":["https://feeds.example/x"],"files":[]}`)
		st.PayloadSHA256 = PayloadDigest(b.Payload)
	}
	for _, tc := range []struct {
		name   string
		mutate func(st *Statement, b *Binding)
		reason string
	}{
		{"shared sensor, feed relay", relay, ""},
		{"organization sensor, feed relay", func(st *Statement, b *Binding) {
			relay(st, b)
			st.SensorScope = ""
			b.Shared, b.TenantID = false, PlatformTenantID
		}, ReasonTenant},
		{"feed relay of an organization", func(st *Statement, b *Binding) {
			relay(st, b)
			st.TenantID = "aaaaaaaa-0000-4000-8000-0000000000ff"
		}, ReasonTenant},
		{"platform tenant on a scan", func(st *Statement, b *Binding) {
			st.SensorScope, st.TenantID = SensorScopeInstance, PlatformTenantID
			b.Shared, b.TenantID = true, ""
		}, ReasonTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			st := f.statement()
			b := f.b
			tc.mutate(&st, &b)
			_, err := f.ver.Verify(context.Background(), f.envelope(t, st), b)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if r := ReasonOf(err); r != tc.reason {
				t.Fatalf("err %v (reason %q), want %q", err, r, tc.reason)
			}
		})
	}
}

// SECURITY: a lookup job runs only on a shared sensor, for an organization
// (its tenant id binds the answer), never with the platform tenant id.
func TestVerify_LookupRules(t *testing.T) {
	const tenant = "aaaaaaaa-0000-4000-8000-0000000000ff"
	lookup := func(st *Statement, b *Binding) {
		st.SensorScope, st.TenantID, st.CommandType, st.Tool, st.Targets = SensorScopeInstance, tenant, CommandTypeLookup, "ctlog", []string{"example.com"}
		b.Shared, b.TenantID, b.CommandType = true, "", CommandTypeLookup
		b.Payload = []byte(`{"scanner":"ctlog","targets":["example.com"],"capability":"lookup.ct@1","input":{"domain":"example.com"}}`)
		st.PayloadSHA256 = PayloadDigest(b.Payload)
	}
	for _, tc := range []struct {
		name   string
		mutate func(st *Statement, b *Binding)
		reason string
	}{
		{"shared sensor, lookup", lookup, ""},
		{"organization sensor, lookup", func(st *Statement, b *Binding) {
			lookup(st, b)
			st.SensorScope = ""
			b.Shared, b.TenantID = false, tenant
		}, ReasonSensorScope},
		{"lookup with the platform tenant", func(st *Statement, b *Binding) {
			lookup(st, b)
			st.TenantID = PlatformTenantID
		}, ReasonTenant},
		{"lookup with no tenant", func(st *Statement, b *Binding) {
			lookup(st, b)
			st.TenantID = ""
		}, ReasonTenant},
		{"lookup statement for another domain", func(st *Statement, b *Binding) {
			lookup(st, b)
			st.Targets = []string{"example.org"}
		}, ReasonTargets},
		{"lookup statement served as a scan", func(st *Statement, b *Binding) {
			lookup(st, b)
			b.CommandType = "scan"
		}, ReasonCommandType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			st := f.statement()
			b := f.b
			tc.mutate(&st, &b)
			_, err := f.ver.Verify(context.Background(), f.envelope(t, st), b)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if r := ReasonOf(err); r != tc.reason {
				t.Fatalf("err %v (reason %q), want %q", err, r, tc.reason)
			}
		})
	}
}
