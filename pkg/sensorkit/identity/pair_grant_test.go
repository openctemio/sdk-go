package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// Threat model (research 452 N3): someone in the middle of the first pairing
// relays the start answer untouched, so the fingerprint the administrator
// compares still matches, then swaps what the sensor learns afterwards: the
// identity, the job signer, the content keys, the TLS anchor. Every one of
// those now comes only from the grant the platform signed with the pairing
// key of the start answer; an answer that is not that grant saves nothing.

// assertNothingSaved: no identity, and no request left to resume.
func assertNothingSaved(t *testing.T, s *Store) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(s.Dir(), IdentityFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("identity.json exists after a refused grant: %v", err)
	}
	if p, _ := s.LoadPending(); p != nil {
		t.Fatalf("pairing.json left behind: %+v", p)
	}
}

func signerJobs(t *testing.T, seed byte) *protov2.SignedJobs {
	t.Helper()
	k := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey))
	return &protov2.SignedJobs{PayloadType: jobsig.PayloadType, Keys: []protov2.SignedJobKey{{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}}}
}

func TestPairRefusesAnAlteredGrant(t *testing.T) {
	attacker := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey))
	_, mitmKey, _ := ed25519.GenerateKey(rand.Reader)
	swapJobKeys := func(_ string, g *pairing.Grant) {
		g.SignedJobs.Keys = []pairing.JobKey{{KeyID: attacker.KeyID, Algorithm: attacker.Algorithm, PublicKey: attacker.PublicKey}}
	}
	cases := []struct {
		name      string
		mitm      func(step string, g *pairing.Grant)
		key       ed25519.PrivateKey
		confirmed bool // the approval grant was fine; only the confirm answer was changed
	}{
		{name: "job keys swapped in the approval answer", mitm: swapJobKeys},
		{name: "job keys swapped and re-signed with the attacker's key", mitm: swapJobKeys, key: mitmKey},
		{name: "job keys swapped in the confirm answer only", confirmed: true, mitm: func(step string, g *pairing.Grant) {
			if step == "confirm" {
				swapJobKeys(step, g)
			}
		}},
		{name: "TLS anchor swapped", confirmed: true, mitm: func(step string, g *pairing.Grant) {
			if step == "confirm" {
				g.TLSAnchors = []string{"sha256:" + strings.Repeat("00", 32)}
			}
		}},
		{name: "content keys swapped", mitm: func(_ string, g *pairing.Grant) {
			g.Identity.ContentSigning = &pairing.ContentSigning{Platform: []pairing.ContentKey{{KeyID: attacker.KeyID, Algorithm: "ed25519", PublicKey: attacker.PublicKey}}}
		}},
		{name: "identity swapped in the confirm answer", confirmed: true, mitm: func(step string, g *pairing.Grant) {
			if step == "confirm" {
				g.Identity.TenantID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			f.signedJobs = signerJobs(t, 3)
			f.mitmGrant, f.mitmKey = c.mitm, c.key
			var out bytes.Buffer
			o := opts(t, srv, &out)
			_, err := Pair(context.Background(), o)
			if !errors.Is(err, pairing.ErrGrantSignature) {
				t.Fatalf("err = %v, want ErrGrantSignature", err)
			}
			if !strings.Contains(err.Error(), pairing.ProblemAnswerUnsigned) || !strings.Contains(err.Error(), "nothing was saved") {
				t.Fatalf("the error does not say what happened: %v", err)
			}
			step := "approval answer"
			if c.confirmed {
				step = "confirm answer"
			}
			if !strings.Contains(err.Error(), step) {
				t.Fatalf("the error does not name the step %q: %v", step, err)
			}
			if f.confirmed != c.confirmed {
				t.Fatalf("confirmed = %v, want %v (a bad approval answer is never confirmed)", f.confirmed, c.confirmed)
			}
			assertNothingSaved(t, o.Store)
		})
	}
}

// A platform from before signed answers: a new sensor never falls back to
// trusting the unsigned identity; it refuses before it confirms.
func TestPairRefusesAnUnsignedPlatform(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.noGrant = true
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.RetryTransient = true
	_, err := Pair(context.Background(), o)
	if !errors.Is(err, pairing.ErrGrantMissing) || !strings.Contains(err.Error(), "upgrade the platform") {
		t.Fatalf("err = %v, want ErrGrantMissing naming the upgrade", err)
	}
	if f.confirmed || f.starts != 1 {
		t.Fatalf("confirmed=%v starts=%d: an unsigned platform must stop the pairing", f.confirmed, f.starts)
	}
	assertNothingSaved(t, o.Store)
}

// The platform's valid grant for another sensor is not valid here.
func TestPairRefusesAnotherSensorsGrant(t *testing.T) {
	f, srv := newFakePlatform(t)
	_, otherSensor, _ := ed25519.GenerateKey(rand.Reader)
	g := &pairing.Grant{PairingID: pid, SensorKey: pairing.Encode(otherSensor.Public().(ed25519.PublicKey)),
		SensorNonce: pairing.Encode(bytes.Repeat([]byte{1}, 32)),
		Identity:    pairing.Identity{SensorID: "11111111-2222-3333-4444-555555555555", TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}}
	sg, err := pairing.SignGrant(f.platformKey, g)
	if err != nil {
		t.Fatal(err)
	}
	f.grantFor = sg
	var out bytes.Buffer
	o := opts(t, srv, &out)
	if _, err := Pair(context.Background(), o); !errors.Is(err, pairing.ErrGrantBinding) {
		t.Fatalf("err = %v, want ErrGrantBinding", err)
	}
	if f.confirmed {
		t.Fatal("confirmed an identity from another sensor's grant")
	}
	assertNothingSaved(t, o.Store)
}

// A grant that names the platform's TLS root CA: the anchor the pairing
// connections verified must be it.
func TestPairChecksTheSignedTLSAnchor(t *testing.T) {
	ca := newTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	httpsec.SetAPIRootCAs(pool)
	t.Cleanup(func() { httpsec.SetAPIRootCAs(nil) })
	sum := sha256.Sum256(ca.cert.RawSubjectPublicKeyInfo)
	anchor := httpsec.FormatFingerprint(sum[:])

	t.Run("named anchor", func(t *testing.T) {
		f, url := tlsFakePlatform(t, ca)
		f.tlsAnchors = []string{"sha256:" + strings.Repeat("ab", 32), strings.ToUpper(anchor)}
		id, _, _ := pairTLS(t, url)
		if id.PlatformTLSPin != anchor {
			t.Fatalf("pin %q, want %q", id.PlatformTLSPin, anchor)
		}
	})
	t.Run("another anchor", func(t *testing.T) {
		f, url := tlsFakePlatform(t, ca)
		// The platform says its certificate comes from another CA: the
		// connection presented a certificate someone else issued.
		f.tlsAnchors = []string{"sha256:" + strings.Repeat("ab", 32)}
		store := NewStore(t.TempDir())
		var out bytes.Buffer
		_, err := Pair(context.Background(), PairOptions{BaseURL: url, Store: store, Out: &out,
			sleep: func(context.Context, time.Duration) error { return nil }})
		if !errors.Is(err, ErrTLSAnchorMismatch) || !strings.Contains(err.Error(), "confirm answer") {
			t.Fatalf("err = %v, want ErrTLSAnchorMismatch", err)
		}
		assertNothingSaved(t, store)
	})
}

// A valid grant pins exactly what it states, and the unsigned identity of
// the poll is not what is saved.
func TestPairSavesWhatTheGrantStates(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.signedJobs = signerJobs(t, 3)
	_, platformKey := contentKey(5)
	_, tenantKey := contentKey(6)
	f.contentSigning = &pairing.ContentSigning{Platform: []pairing.ContentKey{platformKey}, Tenant: []pairing.ContentKey{tenantKey}}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if len(id.JobSigningKeys) != 1 || id.JobSigningKeys[0].KeyID != f.signedJobs.Keys[0].KeyID ||
		len(id.ContentPlatformKeys) != 1 || len(id.ContentTenantKeys) != 1 || id.Name != "dmz-01" {
		t.Fatalf("identity = %+v", id)
	}
}
