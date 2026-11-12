package sensorkit

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// SECURITY: a sensor that bound its own key from an API key has no signed
// pairing grant, so nothing pinned its job signer and it ran with signed
// jobs off: it verified no job and used no job's secrets, silently. Its
// first start against a platform that signs jobs pins the signer the
// platform serves (saved in identity.json) and requires signed jobs from
// then on. A paired identity that pinned nothing (paired to accept unsigned
// jobs) and an operator's SENSOR_REQUIRE_SIGNED_JOBS=false are left alone.
func TestNew_SelfBoundIdentityPinsTheJobSigner(t *testing.T) {
	key := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey))
	for _, tc := range []struct {
		name       string
		paired     bool // the identity came from pairing (platform key set)
		noSigner   bool // the platform does not sign jobs
		requireEnv string
		want       string
		wantPinned bool
		log        string
	}{
		{name: "self-bound, platform signs jobs", want: core.JobsSignedRequired, wantPinned: true, log: "Job signer pinned on first use"},
		{name: "self-bound, platform does not sign jobs", noSigner: true, want: core.JobsSignedOff},
		{name: "paired to accept unsigned jobs", paired: true, want: core.JobsSignedOff},
		{name: "operator turned signed jobs off", requireEnv: "false", want: core.JobsSignedOff, log: core.EnvRequireSignedJobs + "=false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture("") })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			if !tc.noSigner {
				f.SignedJobs = &protov2.SignedJobs{PayloadType: jobsig.PayloadType,
					Keys: []protov2.SignedJobKey{{KeyID: key.KeyID, Algorithm: key.Algorithm, PublicKey: key.PublicKey}}}
			}
			opts, out, errw := baseOptions(t, f)
			opts.APIKey = ""
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
