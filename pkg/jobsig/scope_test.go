package jobsig

import (
	"context"
	"testing"
)

// SECURITY: an organization's sensor refuses a statement signed for a
// shared (instance) sensor, and a shared sensor refuses one that is not:
// neither can be fed the other's jobs.
func TestSensorScope(t *testing.T) {
	const otherTenant = "aaaaaaaa-0000-4000-8000-0000000000ff"
	for _, tc := range []struct {
		name   string
		mutate func(st *Statement, b *Binding)
		reason string
	}{
		{"organization sensor, organization job", func(*Statement, *Binding) {}, ""},
		{"organization sensor, instance job", func(st *Statement, _ *Binding) { st.SensorScope = SensorScopeInstance }, ReasonSensorScope},
		{"organization sensor, unknown scope", func(st *Statement, _ *Binding) { st.SensorScope = "region" }, ReasonSensorScope},
		{"shared sensor, instance job of any tenant", func(st *Statement, b *Binding) {
			st.SensorScope, st.TenantID = SensorScopeInstance, otherTenant
			b.Shared, b.TenantID = true, ""
		}, ""},
		{"shared sensor, organization job", func(_ *Statement, b *Binding) { b.Shared, b.TenantID = true, "" }, ReasonSensorScope},
		{"shared sensor, another sensor's job", func(st *Statement, b *Binding) {
			st.SensorScope, st.SensorID = SensorScopeInstance, "bbbbbbbb-0000-4000-8000-0000000000ff"
			b.Shared, b.TenantID = true, ""
		}, ReasonSensor},
		{"shared sensor, job without a tenant", func(st *Statement, b *Binding) {
			st.SensorScope, st.TenantID = SensorScopeInstance, ""
			b.Shared, b.TenantID = true, ""
		}, ReasonTenant},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, "")
			st := f.statement()
			b := f.b
			tc.mutate(&st, &b)
			got, err := f.ver.Verify(context.Background(), f.envelope(t, st), b)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				if got.TenantID != st.TenantID {
					t.Fatalf("statement tenant %q, want %q", got.TenantID, st.TenantID)
				}
				return
			}
			if r := ReasonOf(err); r != tc.reason {
				t.Fatalf("err %v (reason %q), want %q", err, r, tc.reason)
			}
		})
	}
}

// SECURITY: an organization's sensor refuses a statement that carries
// sensor_scope, "instance" included.
func TestVerify_OrganizationSensorRefusesInstanceScope(t *testing.T) {
	for _, scope := range []string{SensorScopeInstance, "region", "x"} {
		f := newFixture(t, "")
		st := f.statement()
		st.SensorScope = scope
		if _, err := f.ver.Verify(context.Background(), f.envelope(t, st), f.b); ReasonOf(err) != ReasonSensorScope {
			t.Errorf("scope %q: err %v, want reason %s", scope, err, ReasonSensorScope)
		}
	}
}

// SECURITY: a shared sensor accepts an instance job of any organization
// only for its own sensor id, and returns the signed tenant to bind the
// job's results to.
func TestVerify_SharedSensorRequiresInstanceScopeAndOwnSensor(t *testing.T) {
	f := newFixture(t, "")
	st := f.statement()
	st.SensorScope, st.TenantID = SensorScopeInstance, "aaaaaaaa-0000-4000-8000-0000000000ee"
	b := f.b
	b.Shared, b.TenantID = true, ""
	got, err := f.ver.Verify(context.Background(), f.envelope(t, st), b)
	if err != nil || got.TenantID != st.TenantID || got.CommandID != b.CommandID {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// SECURITY: a zone (private ranges) is signed only for a shared sensor's
// job: an organization's sensor refuses a statement that carries one, and
// a shared sensor returns the signed zone.
func TestVerify_ZoneOnlyForSharedSensors(t *testing.T) {
	zone := &Zone{ID: "aaaaaaaa-0000-4000-8000-0000000000aa", Ranges: []string{"10.20.0.0/16"}}
	f := newFixture(t, "")
	st := f.statement()
	st.Zone = zone
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st), f.b); ReasonOf(err) != ReasonSensorScope {
		t.Fatalf("organization sensor accepted a zone: %v", err)
	}
	f = newFixture(t, "")
	st = f.statement()
	st.SensorScope, st.TenantID, st.Zone = SensorScopeInstance, "aaaaaaaa-0000-4000-8000-0000000000ee", zone
	b := f.b
	b.Shared, b.TenantID = true, ""
	got, err := f.ver.Verify(context.Background(), f.envelope(t, st), b)
	if err != nil || got.Zone == nil || got.Zone.Ranges[0] != "10.20.0.0/16" {
		t.Fatalf("got %+v, %v", got, err)
	}
	f = newFixture(t, "")
	st = f.statement()
	st.SensorScope, st.TenantID, st.Zone = SensorScopeInstance, "aaaaaaaa-0000-4000-8000-0000000000ee", &Zone{ID: "x"}
	b = f.b
	b.Shared, b.TenantID = true, ""
	if _, err := f.ver.Verify(context.Background(), f.envelope(t, st), b); ReasonOf(err) != ReasonSensorScope {
		t.Fatalf("a zone without ranges was accepted: %v", err)
	}
}
