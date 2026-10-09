package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// JobSigningStateFile keeps, in the state directory, the last job sequence
// number accepted from each signer key (replay protection across
// restarts).
const JobSigningStateFile = "job-signing-seq.json"

// ResolveRequireSignedJobs decides whether the sensor refuses commands
// without a valid job signature: SENSOR_REQUIRE_SIGNED_JOBS when set, else
// true when the identity pinned job-signing keys at pairing (a sensor
// paired by this SDK with a platform that signs jobs), else false.
func ResolveRequireSignedJobs(pinnedAtPairing int) (required bool, from string, err error) {
	v, set, err := core.RequireSignedJobsFromEnv(nil)
	if err != nil {
		return false, "", usageError(err)
	}
	if set {
		return v, requireFromEnv, nil
	}
	if pinnedAtPairing > 0 {
		return true, requireFromIdentity, nil
	}
	return false, "", nil
}

// resolveJobSigning builds the poller's JobGuard from the keys of
// SENSOR_JOB_SIGNING_KEYS and identity.json and the requirement, and sets
// the posture it reports. A sensor that runs no platform commands has
// none.
func (k *Kit) resolveJobSigning() error {
	s := &k.s
	if k.opts.Standalone || !s.commands || k.client == nil {
		return nil
	}
	envKeys, err := jobsig.ParseKeys(envOr(k.opts.JobSigningKeys, EnvJobSigningKeys))
	if err != nil {
		return usageError(fmt.Errorf("%s: %w", EnvJobSigningKeys, err))
	}
	var idKeys *jobsig.Keys
	pinned := 0
	if s.identity != nil && len(s.identity.JobSigningKeys) > 0 {
		if idKeys, err = jobsig.FromPublicKeys(s.identity.JobSigningKeys); err != nil {
			return usageError(fmt.Errorf("identity: job_signing_keys: %w; pair again", err))
		}
		pinned = idKeys.Len()
	}
	keys := envKeys.Merge(idKeys)
	required, from, err := ResolveRequireSignedJobs(pinned)
	if err != nil {
		return err
	}

	var tenantID, sensorID string
	if s.identity != nil {
		tenantID, sensorID = s.identity.TenantID, s.identity.SensorID
	}
	var v *jobsig.Verifier
	if keys.Len() > 0 {
		if tenantID == "" || sensorID == "" {
			return usageError(fmt.Errorf("%s / %s: signed jobs are verified against the sensor's own organization and id, which only a paired (key-bound) sensor knows; pair the sensor or unset them",
				EnvJobSigningKeys, core.EnvRequireSignedJobs))
		}
		cl := k.client
		v, err = jobsig.NewVerifier(jobsig.Config{
			Keys:      keys,
			StateFile: filepath.Join(s.stateDir, JobSigningStateFile),
			// A key pinned by id gets its public key from the hello; only
			// a listed key whose recomputed id is pinned is used.
			KeySource: func(ctx context.Context) ([]jobsig.PublicKey, error) {
				h, err := cl.Hello(ctx)
				if err != nil {
					return nil, err
				}
				if h.SignedJobs == nil {
					return nil, errors.New("the platform lists no job-signing keys")
				}
				out := make([]jobsig.PublicKey, 0, len(h.SignedJobs.Keys))
				for _, pk := range h.SignedJobs.Keys {
					out = append(out, jobsig.PublicKey{KeyID: pk.KeyID, Algorithm: pk.Algorithm, PublicKey: pk.PublicKey})
				}
				return out, nil
			},
		})
		if err != nil {
			return usageError(err)
		}
	}
	g, err := core.NewJobGuard(v, required, tenantID, sensorID)
	if err != nil {
		return usageError(err)
	}
	s.jobs = g
	core.SetJobsPosture(g.Posture())

	switch g.Posture() {
	case core.JobsSignedRequired:
		how := "paired by this SDK"
		if from == requireFromEnv {
			how = core.EnvRequireSignedJobs + "=true"
		}
		_, _ = fmt.Fprintf(k.out, "  Signed jobs: required (%s); signer keys %s\n", how, strings.Join(keys.IDs(), ", "))
	case core.JobsSignedVerifiedWhenPresent:
		_, _ = fmt.Fprintf(k.errw, "Warning: signed jobs: verified when present, unsigned jobs still run (signer keys %s); set %s=true to refuse them\n",
			strings.Join(keys.IDs(), ", "), core.EnvRequireSignedJobs)
	default:
		if s.verbose {
			_, _ = fmt.Fprintf(k.out, "  Signed jobs: off (no job-signing key pinned; set %s or pair again)\n", EnvJobSigningKeys)
		}
	}
	return nil
}
