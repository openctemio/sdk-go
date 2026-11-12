package sensorkit

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32))
}

func signedJobsOf(priv ed25519.PrivateKey) *protov2.SignedJobs {
	key := jobsig.NewPublicKey(priv.Public().(ed25519.PublicKey))
	return &protov2.SignedJobs{PayloadType: jobsig.PayloadType,
		Keys: []protov2.SignedJobKey{{KeyID: key.KeyID, Algorithm: key.Algorithm, PublicKey: key.PublicKey}}}
}

// overTLS serves f over https with a certificate the API client trusts (as
// a platform with a public certificate is trusted through the trust store)
// and returns its URL.
func overTLS(t *testing.T, f *conformance.FakePlatform) string {
	t.Helper()
	srv := httptest.NewTLSServer(f.Server.Config.Handler)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	httpsec.SetAPIRootCAs(pool)
	t.Cleanup(func() { httpsec.SetAPIRootCAs(nil) })
	return srv.URL
}

// selfBoundKit starts a self-bound sensor (identity without a platform
// pairing key) against f, served at apiURL; stateDir "" is a new one.
func selfBoundKit(t *testing.T, f *conformance.FakePlatform, apiURL, stateDir string) (*Kit, *identity.Store, string) {
	t.Helper()
	opts, out, errw := baseOptions(t, f)
	opts.APIKey, opts.APIURL = "", apiURL
	if stateDir == "" {
		pairedStore(t, opts.StateDir)
	} else {
		opts.StateDir = stateDir
	}
	st := identity.NewStore(opts.StateDir)
	sg, err := st.LoadKey()
	if err != nil {
		t.Fatal(err)
	}
	f.TrustSensorKey(sg.PublicKey())
	k, err := New(opts)
	if err != nil {
		t.Fatalf("start: %v\nstderr %s", err, errw.String())
	}
	t.Cleanup(k.closeClient)
	return k, st, out.String() + errw.String()
}

// SECURITY: a sensor that bound its own key from an API key has no signed
// pairing grant, so nothing pinned its job signer and it ran with signed
// jobs off: it verified no job and used no job's secrets, silently. Its
// first start against a platform that signs jobs, over https, pins the
// signer the platform serves (saved in identity.json) and requires signed
// jobs from then on. A paired identity that pinned nothing (paired to
// accept unsigned jobs) and an operator's SENSOR_REQUIRE_SIGNED_JOBS=false
// are left alone. Over plain http nothing is pinned: a network attacker
// could serve its own signer and have it pinned for good.
func TestNew_SelfBoundIdentityPinsTheJobSigner(t *testing.T) {
	key := jobsig.NewPublicKey(seedKey(7).Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name       string
		plainHTTP  bool // SENSOR_API_URL is http://
		paired     bool // the identity came from pairing (platform key set)
		noSigner   bool // the platform does not sign jobs
		requireEnv string
		want       string
		wantPinned bool
		log        string
	}{
		{name: "self-bound, platform signs jobs", want: core.JobsSignedRequired, wantPinned: true, log: "Job signer pinned on first use"},
		{name: "self-bound over plain http", plainHTTP: true, want: core.JobsSignedOff, log: "the platform URL is not https"},
		{name: "self-bound, platform does not sign jobs", noSigner: true, want: core.JobsSignedOff},
		{name: "paired to accept unsigned jobs", paired: true, want: core.JobsSignedOff},
		{name: "operator turned signed jobs off", requireEnv: "false", want: core.JobsSignedOff, log: core.EnvRequireSignedJobs + "=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture("") })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			if !tc.noSigner {
				f.SignedJobs = signedJobsOf(seedKey(7))
			}
			apiURL := f.URL()
			if !tc.plainHTTP {
				apiURL = overTLS(t, f)
			}
			opts, out, errw := baseOptions(t, f)
			opts.APIKey, opts.APIURL = "", apiURL
			pairedStore(t, opts.StateDir)
			st := identity.NewStore(opts.StateDir)
			sg, err := st.LoadKey()
			if err != nil {
				t.Fatal(err)
			}
			f.TrustSensorKey(sg.PublicKey())
			if tc.paired {
				id, _, err := st.Load()
				if err != nil {
					t.Fatal(err)
				}
				id.PlatformKey = "cGxhdGZvcm0ta2V5"
				if err := st.Save(id); err != nil {
					t.Fatal(err)
				}
			}
			if tc.requireEnv != "" {
				t.Setenv(core.EnvRequireSignedJobs, tc.requireEnv)
			}
			k, err := New(opts)
			if err != nil {
				t.Fatalf("start: %v\nstderr %s", err, errw.String())
			}
			t.Cleanup(k.closeClient)
			if got := k.s.jobs.Posture(); got != tc.want {
				t.Fatalf("posture %s, want %s\nstderr %s", got, tc.want, errw.String())
			}
			id, _, err := st.Load()
			if err != nil {
				t.Fatal(err)
			}
			pinned := len(id.JobSigningKeys) == 1 && id.JobSigningKeys[0].KeyID == key.KeyID
			if pinned != tc.wantPinned || (!tc.wantPinned && (len(id.JobSigningKeys) > 0 || id.JobSigningRoot != "")) {
				t.Fatalf("identity.json job signer: keys %+v root %q, want pinned=%v", id.JobSigningKeys, id.JobSigningRoot, tc.wantPinned)
			}
			if tc.log != "" && !strings.Contains(out.String()+errw.String(), tc.log) {
				t.Fatalf("log lacks %q:\nstdout %s\nstderr %s", tc.log, out.String(), errw.String())
			}
		})
	}
}

// SECURITY: a hello that cannot be read leaves the sensor unpinned with a
// warning at that start (and every start until one reads it), not silently.
func TestNew_SelfBoundSignerHelloFailureWarns(t *testing.T) {
	t.Cleanup(func() { core.SetJobsPosture("") })
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	f.SignedJobs = signedJobsOf(seedKey(7))
	apiURL := overTLS(t, f)
	httpsec.SetAPIRootCAs(x509.NewCertPool()) // the platform's certificate is not trusted
	k, st, logs := selfBoundKit(t, f, apiURL, "")
	if got := k.s.jobs.Posture(); got != core.JobsSignedOff {
		t.Fatalf("posture %s, want off", got)
	}
	if !strings.Contains(logs, "job signer could not be read") || !strings.Contains(logs, EnvJobSigningRoot) {
		t.Fatalf("no warning that the signer is not pinned:\n%s", logs)
	}
	id, _, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(id.JobSigningKeys) > 0 || id.JobSigningRoot != "" {
		t.Fatalf("pinned %+v %q from a hello it could not read", id.JobSigningKeys, id.JobSigningRoot)
	}
}

// SECURITY: a pin taken on first use is never replaced: a later start whose
// hello serves another signer keeps the first one and refuses the jobs the
// other one signs.
func TestNew_SelfBoundSignerPinIsNotReplaced(t *testing.T) {
	t.Cleanup(func() { core.SetJobsPosture("") })
	first, second := seedKey(7), seedKey(9)
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	f.SignedJobs = signedJobsOf(first)
	apiURL := overTLS(t, f)
	k, st, _ := selfBoundKit(t, f, apiURL, "")
	stateDir := k.s.stateDir
	k.closeClient()

	f.SignedJobs = signedJobsOf(second)
	k, _, logs := selfBoundKit(t, f, apiURL, stateDir)
	id, _, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	firstID := jobsig.KeyID(first.Public().(ed25519.PublicKey))
	if len(id.JobSigningKeys) != 1 || id.JobSigningKeys[0].KeyID != firstID {
		t.Fatalf("the pin changed: %+v", id.JobSigningKeys)
	}
	if strings.Contains(logs, "Job signer pinned on first use") {
		t.Fatalf("pinned again at the second start:\n%s", logs)
	}
	if got := k.s.jobs.Posture(); got != core.JobsSignedRequired {
		t.Fatalf("posture %s, want required", got)
	}
	ctx := context.Background()
	if err := k.s.jobs.Check(ctx, signedCommand(t, first, id, "cccccccc-0000-4000-8000-000000000001")); err != nil {
		t.Fatalf("a job of the pinned signer was refused: %v", err)
	}
	if err := k.s.jobs.Check(ctx, signedCommand(t, second, id, "cccccccc-0000-4000-8000-000000000002")); err == nil {
		t.Fatal("a job of the signer the second hello served was accepted")
	}
}

// A hello that serves a valid key set pins its root, not the signer keys:
// the root's key set says which keys are valid, so a rotation (the platform
// serving a new key set of the same root) is followed without a new pin.
func TestNew_SelfBoundSignerPinsTheKeySetRoot(t *testing.T) {
	t.Cleanup(func() { core.SetJobsPosture(""); core.SetJobsKeySet(nil) })
	root, oldSigner, newSigner := seedKey(3), seedKey(7), seedKey(9)
	rootID := jobsig.KeyID(root.Public().(ed25519.PublicKey))
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	sj := signedJobsOf(oldSigner)
	sj.KeySet = keySetOf(t, root, 1, time.Now().Add(-time.Hour), oldSigner)
	f.SignedJobs = sj
	k, st, logs := selfBoundKit(t, f, overTLS(t, f), "")
	id, _, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if id.JobSigningRoot != rootID || len(id.JobSigningKeys) != 0 {
		t.Fatalf("identity.json: root %q keys %+v, want root %s and no keys\n%s", id.JobSigningRoot, id.JobSigningKeys, rootID, logs)
	}
	if !strings.Contains(logs, "root "+rootID) {
		t.Fatalf("the pin line does not name the root:\n%s", logs)
	}
	ctx := context.Background()
	if err := k.s.jobs.Check(ctx, signedCommand(t, oldSigner, id, "cccccccc-0000-4000-8000-000000000001")); err != nil {
		t.Fatalf("a job of the key set's signer was refused: %v", err)
	}
	stateDir := k.s.stateDir
	k.closeClient()

	// Rotation: the platform serves a newer key set of the same root that
	// lists another signer. The next start follows it with the same pin.
	rotated := signedJobsOf(newSigner)
	rotated.KeySet = keySetOf(t, root, 2, time.Now(), newSigner)
	f.SignedJobs = rotated
	k, _, logs = selfBoundKit(t, f, f.URL(), stateDir)
	if strings.Contains(logs, "Job signer pinned on first use") {
		t.Fatalf("pinned again after the rotation:\n%s", logs)
	}
	if after, _, err := st.Load(); err != nil || after.JobSigningRoot != rootID || len(after.JobSigningKeys) != 0 {
		t.Fatalf("identity.json after the rotation: %+v %v", after, err)
	}
	if err := k.s.jobs.Check(ctx, signedCommand(t, newSigner, id, "cccccccc-0000-4000-8000-000000000002")); err != nil {
		t.Fatalf("a job of the rotated signer was refused: %v", err)
	}
	if err := k.s.jobs.Check(ctx, signedCommand(t, oldSigner, id, "cccccccc-0000-4000-8000-000000000003")); err == nil {
		t.Fatal("a job of the signer the rotation removed was accepted")
	}
}

// keySetOf signs version of a key set listing keys with root, issued at
// issued.
func keySetOf(t *testing.T, root ed25519.PrivateKey, version uint64, issued time.Time, keys ...ed25519.PrivateKey) []byte {
	t.Helper()
	rootPub := root.Public().(ed25519.PublicKey)
	ks := jobsig.KeySet{Kind: jobsig.KeySetKind, Version: version, IssuedAt: issued.UTC().Truncate(time.Second),
		NotAfter: issued.UTC().Truncate(time.Second).Add(24 * time.Hour), RootKeyID: jobsig.KeyID(rootPub),
		RootPublicKey: base64.StdEncoding.EncodeToString(rootPub)}
	for _, k := range keys {
		ks.Keys = append(ks.Keys, jobsig.NewPublicKey(k.Public().(ed25519.PublicKey)))
	}
	p, err := json.Marshal(ks)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(jobsig.Envelope{PayloadType: jobsig.KeySetPayloadType, Payload: p,
		Signatures: []jobsig.Signature{{KeyID: ks.RootKeyID, Sig: ed25519.Sign(root, jobsig.PreAuthEncoding(jobsig.KeySetPayloadType, p))}}})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

var signedSeq uint64

// signedCommand is a scan command for id's sensor signed by priv.
func signedCommand(t *testing.T, priv ed25519.PrivateKey, id *identity.Identity, cmdID string) *core.Command {
	t.Helper()
	signedSeq++
	payload := []byte(`{"scanner":"nuclei","targets":["a.example.com"]}`)
	now := time.Now()
	nonce := make([]byte, jobsig.NonceBytes)
	nonce[0], nonce[1] = byte(signedSeq), byte(signedSeq>>8)
	keyID := jobsig.KeyID(priv.Public().(ed25519.PublicKey))
	st := jobsig.Statement{Kind: jobsig.Kind, TenantID: id.TenantID, SensorID: id.SensorID, CommandID: cmdID,
		CommandType: "scan", Tool: "nuclei", PayloadSHA256: jobsig.PayloadDigest(payload), Targets: []string{"a.example.com"},
		IssuedAt: now.Add(-10 * time.Second), ExpiresAt: now.Add(50 * time.Minute), Seq: signedSeq,
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Signer: &jobsig.SignerRef{KeyID: keyID}}
	p, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	env, err := json.Marshal(jobsig.Envelope{PayloadType: jobsig.PayloadType, Payload: p,
		Signatures: []jobsig.Signature{{KeyID: keyID, Sig: ed25519.Sign(priv, jobsig.PreAuthEncoding(jobsig.PayloadType, p))}}})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Command{ID: cmdID, Type: "scan", Payload: payload, SignedJob: env}
}
