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
