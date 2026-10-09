package sensorkit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// JobSigningStateFile keeps, in the state directory, the last job sequence
// number accepted from each signer key (replay protection across
// restarts).
const JobSigningStateFile = "job-signing-seq.json"

// JobSigningKeySetFile keeps, in the state directory, the job-signing key
// set accepted last from the pinned root (so its version never goes down,
// across restarts too).
const JobSigningKeySetFile = "job-signing-keyset.json"

// KeySetWarnBefore is how long before a key set expires the sensor warns
// that the platform must deploy a new one.
const KeySetWarnBefore = 7 * 24 * time.Hour

// keySetStartTimeout bounds the key set fetch at start.
const keySetStartTimeout = 10 * time.Second

// ResolveRequireSignedJobs decides whether the sensor refuses commands
// without a valid job signature: SENSOR_REQUIRE_SIGNED_JOBS when set, else
// true when the identity pinned job-signing keys or a root at pairing (a
// sensor paired by this SDK with a platform that signs jobs), else false.
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

// resolveJobSigning builds the poller's JobGuard from the root and keys of
// SENSOR_JOB_SIGNING_ROOT, SENSOR_JOB_SIGNING_KEYS and identity.json and
// the requirement, and sets the posture it reports. With a root, the keys
// pinned at pairing are not used: the root's current key set says which
// signer keys are valid. A sensor that runs no platform commands has none.
func (k *Kit) resolveJobSigning() error {
	s := &k.s
	if k.opts.Standalone || !s.commands || k.client == nil {
		return nil
	}
	envKeys, err := jobsig.ParseKeys(envOr(k.opts.JobSigningKeys, EnvJobSigningKeys))
	if err != nil {
		return usageError(fmt.Errorf("%s: %w", EnvJobSigningKeys, err))
	}
	root, err := jobsig.ParseRoot(envOr(k.opts.JobSigningRoot, EnvJobSigningRoot))
	if err != nil {
		return usageError(fmt.Errorf("%s: %w", EnvJobSigningRoot, err))
	}
	pinned := 0
	if s.identity != nil && s.identity.JobSigningRoot != "" {
		idRoot, err := jobsig.ParseRoot(s.identity.JobSigningRoot)
		if err != nil || !strings.HasPrefix(s.identity.JobSigningRoot, "SHA256:") {
			return usageError(errors.New("identity: job_signing_root is not a SHA256:<hex> key id; pair again"))
		}
		if root == "" {
			root = idRoot
		}
		pinned++
	}
	var idKeys *jobsig.Keys
	if s.identity != nil && len(s.identity.JobSigningKeys) > 0 {
		if idKeys, err = jobsig.FromPublicKeys(s.identity.JobSigningKeys); err != nil {
			return usageError(fmt.Errorf("identity: job_signing_keys: %w; pair again", err))
		}
		pinned += idKeys.Len()
		if root != "" {
			idKeys = nil // the root's key set replaces the keys pinned at pairing
		}
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
	cl := k.client
	var trust *jobsig.KeySetTrust
	if root != "" {
		if trust, err = jobsig.NewKeySetTrust(jobsig.KeySetConfig{
			Root:      root,
			StateFile: filepath.Join(s.stateDir, JobSigningKeySetFile),
			Source: func(ctx context.Context) ([]byte, error) {
				h, err := cl.Hello(ctx)
				if err != nil {
					return nil, err
				}
				if h.SignedJobs == nil {
					return nil, nil
				}
				return h.SignedJobs.KeySet, nil
			},
			OnChange: func(ks *jobsig.KeySet) { reportKeySet(k.out, k.errw, ks, time.Now()) },
		}); err != nil {
			return usageError(err)
		}
	}
	var v *jobsig.Verifier
	if keys.Len() > 0 || trust != nil {
		if tenantID == "" || sensorID == "" {
			return usageError(fmt.Errorf("%s / %s / %s: signed jobs are verified against the sensor's own organization and id, which only a paired (key-bound) sensor knows; pair the sensor or unset them",
				EnvJobSigningRoot, EnvJobSigningKeys, core.EnvRequireSignedJobs))
		}
		v, err = jobsig.NewVerifier(jobsig.Config{
			Keys:      keys,
			KeySet:    trust,
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
	core.SetJobsKeySet(trust)

	signers := strings.Join(keys.IDs(), ", ")
	if trust != nil {
		signers = "the key set of root " + root
		if ids := keys.IDs(); len(ids) > 0 {
			signers += " and " + strings.Join(ids, ", ")
		}
	}
	switch g.Posture() {
	case core.JobsSignedRequired:
		how := "paired by this SDK"
		if from == requireFromEnv {
			how = core.EnvRequireSignedJobs + "=true"
		}
		_, _ = fmt.Fprintf(k.out, "  Signed jobs: required (%s); signer keys from %s\n", how, signers)
	case core.JobsSignedVerifiedWhenPresent:
		_, _ = fmt.Fprintf(k.errw, "Warning: signed jobs: verified when present, unsigned jobs still run (signer keys from %s); set %s=true to refuse them\n",
			signers, core.EnvRequireSignedJobs)
	default:
		if s.verbose {
			_, _ = fmt.Fprintf(k.out, "  Signed jobs: off (no job-signing key or root pinned; set %s or pair again)\n", EnvJobSigningRoot)
		}
	}
	if trust != nil {
		k.startKeySet(trust)
	}
	return nil
}

// startKeySet fetches the root's key set once at start. Without a valid
// one, signed jobs are refused (rule job_keyset) until one is accepted;
// each check fetches it again.
func (k *Kit) startKeySet(trust *jobsig.KeySetTrust) {
	ctx, cancel := context.WithTimeout(context.Background(), keySetStartTimeout)
	defer cancel()
	err := trust.Refresh(ctx, true)
	ks := trust.Current()
	switch {
	case ks == nil && err != nil:
		_, _ = fmt.Fprintf(k.errw, "Warning: no job-signing key set from root %s yet (%v); signed jobs are refused until the platform serves a valid one\n", trust.Root(), err)
	case ks == nil:
		_, _ = fmt.Fprintf(k.errw, "Warning: the platform serves no job-signing key set for root %s; signed jobs are refused until it does\n", trust.Root())
	default:
		if err != nil {
			_, _ = fmt.Fprintf(k.errw, "Warning: the platform's job-signing key set was refused (%v); keeping version %d\n", err, ks.Version)
		}
		reportKeySet(k.out, k.errw, ks, time.Now())
	}
}

// reportKeySet logs the accepted key set, with a warning when it expires
// within KeySetWarnBefore (or has expired).
func reportKeySet(out, errw io.Writer, ks *jobsig.KeySet, now time.Time) {
	exp := ks.NotAfter.UTC().Format(time.RFC3339)
	switch left := ks.NotAfter.Sub(now); {
	case left <= 0:
		_, _ = fmt.Fprintf(errw, "Warning: job-signing key set version %d expired at %s; signed jobs are refused until the platform deploys a new one\n", ks.Version, exp)
	case left <= KeySetWarnBefore:
		_, _ = fmt.Fprintf(errw, "Warning: job-signing key set version %d expires at %s; the platform must deploy a new one before then\n", ks.Version, exp)
	default:
		_, _ = fmt.Fprintf(out, "  Job-signing key set: version %d, %d key(s), expires %s\n", ks.Version, len(ks.Keys), exp)
	}
}
