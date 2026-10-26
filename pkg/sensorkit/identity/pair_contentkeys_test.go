package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

func contentKey(seed byte) (jobsig.PublicKey, pairing.ContentKey) {
	pub := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, 32)).Public().(ed25519.PublicKey)
	k := jobsig.NewPublicKey(pub)
	return k, pairing.ContentKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
}

// Pairing pins the content-signing keys the granted identity lists, with each
// key id recomputed: a key listed under another key's id is not pinned.
func TestPairPinsContentKeys(t *testing.T) {
	f, srv := newFakePlatform(t)
	platform, platformWire := contentKey(5)
	tenant, tenantWire := contentKey(6)
	_, forged := contentKey(7)
	forged.KeyID = platform.KeyID
	f.contentSigning = &pairing.ContentSigning{Platform: []pairing.ContentKey{platformWire, forged}, Tenant: []pairing.ContentKey{tenantWire}}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if len(id.ContentPlatformKeys) != 1 || id.ContentPlatformKeys[0] != platform || len(id.ContentTenantKeys) != 1 || id.ContentTenantKeys[0] != tenant {
		t.Fatalf("pinned %+v / %+v", id.ContentPlatformKeys, id.ContentTenantKeys)
	}
	got, _, err := o.Store.Load()
	if err != nil || len(got.ContentPlatformKeys) != 1 || len(got.ContentTenantKeys) != 1 {
		t.Fatalf("identity.json: %v %+v", err, got)
	}
	if !strings.Contains(out.String(), "Content keys pinned: 1 platform, 1 organization") || !strings.Contains(out.String(), "not pinned") {
		t.Fatalf("output:\n%s", out.String())
	}
}

// A shared sensor takes the platform key only: it never holds an
// organization's packs, so an organization key the platform lists is ignored.
func TestPairInstanceTakesNoTenantContentKey(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.instance = true
	platform, platformWire := contentKey(5)
	_, tenantWire := contentKey(6)
	f.contentSigning = &pairing.ContentSigning{Platform: []pairing.ContentKey{platformWire}, Tenant: []pairing.ContentKey{tenantWire}}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.EnrollmentToken = "tok"
	id, err := Pair(context.Background(), o)
	if err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if len(id.ContentPlatformKeys) != 1 || id.ContentPlatformKeys[0] != platform || len(id.ContentTenantKeys) != 0 {
		t.Fatalf("pinned %+v / %+v", id.ContentPlatformKeys, id.ContentTenantKeys)
	}
}

func TestPairWithoutContentKeysPinsNone(t *testing.T) {
	_, srv := newFakePlatform(t)
	var out bytes.Buffer
	id, err := Pair(context.Background(), opts(t, srv, &out))
	if err != nil || len(id.ContentPlatformKeys)+len(id.ContentTenantKeys) != 0 {
		t.Fatalf("%v %+v", err, id)
	}
}
