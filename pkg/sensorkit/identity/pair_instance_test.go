package identity

// Shared sensor enrollment with an instance enrollment token (api RFC-100
// §7): the token rides in the signed start request, is never printed, the
// identity must be a shared sensor's (no tenant), a refused token stops at
// once, and a spent token never starts a second request.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

const testToken = "octe_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1eF3hJ5kL7nP9rS1uX3w"

func TestPairWithEnrollmentTokenEnrollsASharedSensor(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.EnrollmentToken = testToken
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if f.lastToken != testToken || !f.confirmed || f.unsigned != 0 {
		t.Fatalf("token sent %q confirmed=%v unsigned=%d", f.lastToken, f.confirmed, f.unsigned)
	}
	if id.Scope != pairing.ScopeInstance || id.TenantID != "" {
		t.Fatalf("identity %+v", id)
	}
	got, _, err := o.Store.Load()
	if err != nil || got.Scope != pairing.ScopeInstance || got.TenantID != "" {
		t.Fatalf("stored identity %+v (%v)", got, err)
	}
	if strings.Contains(out.String(), "octe_") || strings.Contains(out.String(), "Code:") ||
		!strings.Contains(out.String(), "shared sensor") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestPairWithEnrollmentTokenRefusesAnOrganizationIdentity(t *testing.T) {
	f, srv := newFakePlatform(t) // grants a tenant identity
	o := opts(t, srv, io.Discard)
	o.EnrollmentToken = testToken
	if _, err := Pair(context.Background(), o); err == nil || f.confirmed {
		t.Fatalf("err = %v confirmed = %v", err, f.confirmed)
	}
	if _, _, err := o.Store.Load(); !errors.Is(err, ErrNoIdentity) {
		t.Fatalf("an identity was saved: %v", err)
	}
}

// Without a token, an identity without a tenant is refused.
func TestPairRefusesASharedIdentityWithoutAToken(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	o := opts(t, srv, io.Discard)
	if _, err := Pair(context.Background(), o); err == nil || f.confirmed {
		t.Fatalf("err = %v confirmed = %v", err, f.confirmed)
	}
}

func TestPairWithARefusedEnrollmentTokenStops(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.refuseToken = true
	o := opts(t, srv, io.Discard)
	o.EnrollmentToken = testToken
	o.Retry = true
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrEnrollmentRefused) {
		t.Fatalf("err = %v", err)
	}
	if f.starts != 1 {
		t.Fatalf("starts = %d, want 1", f.starts)
	}
}

func TestPairWithASpentEnrollmentTokenDoesNotRetry(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	f.finalStatus = pairing.StatusExpired
	o := opts(t, srv, io.Discard)
	o.EnrollmentToken = testToken
	o.Retry = true
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v", err)
	}
	if f.starts != 1 {
		t.Fatalf("starts = %d, want 1", f.starts)
	}
}

func TestPairEnrollmentTokenExcludesCodeAndRepair(t *testing.T) {
	_, srv := newFakePlatform(t)
	for _, mut := range []func(*PairOptions){
		func(o *PairOptions) { o.Code = "K7QM-4ZTD" },
		func(o *PairOptions) { o.RepairSensorID = "11111111-2222-3333-4444-555555555555" },
	} {
		o := opts(t, srv, io.Discard)
		o.EnrollmentToken = testToken
		mut(&o)
		if _, err := Pair(context.Background(), o); err == nil {
			t.Fatal("a token combined with a code or a re-pair was accepted")
		}
	}
}

// An organization enrollment token: sent with the organization scope, the
// identity must name an organization, the fingerprint is printed (an
// administrator may have to compare it), the token never is.
func TestPairWithOrganizationTokenJoinsTheOrganization(t *testing.T) {
	f, srv := newFakePlatform(t) // grants a tenant identity
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.EnrollmentToken = testToken
	o.OrganizationEnrollment = true
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if f.lastToken != testToken || f.lastScope != pairing.EnrollmentScopeOrganization || !f.confirmed {
		t.Fatalf("token %q scope %q confirmed=%v", f.lastToken, f.lastScope, f.confirmed)
	}
	if id.Scope != "" || id.TenantID == "" {
		t.Fatalf("identity %+v", id)
	}
	if strings.Contains(out.String(), "octe_") || !strings.Contains(out.String(), "Fingerprint:") ||
		strings.Contains(out.String(), "shared sensor") {
		t.Fatalf("output:\n%s", out.String())
	}
}

func TestPairWithOrganizationTokenRefusesASharedIdentity(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	o := opts(t, srv, io.Discard)
	o.EnrollmentToken = testToken
	o.OrganizationEnrollment = true
	if _, err := Pair(context.Background(), o); err == nil || f.confirmed {
		t.Fatalf("err = %v confirmed = %v", err, f.confirmed)
	}
}

// An instance token never carries the organization scope.
func TestPairWithInstanceTokenSendsNoScope(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	o := opts(t, srv, io.Discard)
	o.EnrollmentToken = testToken
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if f.lastScope != "" {
		t.Fatalf("scope %q sent with an instance token", f.lastScope)
	}
}
