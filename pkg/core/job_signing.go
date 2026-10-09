package core

// Signed jobs (api docs/rfcs/RFC-040-platform-sensor-mutual-distrust.md
// §5.6, decision Q11): the platform's separate job signer signs every
// command a claim hands out, and a sensor that pins the signer's key
// verifies the signature and the statement's binding (this sensor, this
// command, its payload bytes, its lease, the validity window, no replay)
// before the command is started or any executor sees it (pkg/jobsig). A
// command that fails, or comes unsigned to a sensor that requires signed
// jobs, is refused with rule "job_signature" and never run.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// EnvRequireSignedJobs overrides whether the sensor requires signed jobs:
// true refuses every command without a valid signature; false runs unsigned
// commands (a signed one is still verified when a key is pinned). Unset:
// required when the identity pinned job-signing keys at pairing.
const EnvRequireSignedJobs = "SENSOR_REQUIRE_SIGNED_JOBS"

// RefusalRuleJobSignature is the rule of a command refused for its job
// signature.
const RefusalRuleJobSignature = "job_signature"

// RefusalRuleJobKeySet is the rule of a signed command refused because the
// sensor pins a job-signing root and holds no valid key set (none yet,
// expired, or refused).
const RefusalRuleJobKeySet = "job_keyset"

// Job signing postures (JobsPosture.Signed).
const (
	// JobsSignedRequired: every command must carry a signed job that
	// verifies.
	JobsSignedRequired = "required"
	// JobsSignedVerifiedWhenPresent: a signed job is verified; an unsigned
	// command runs (a legacy install with pinned keys).
	JobsSignedVerifiedWhenPresent = "verified_when_present"
	// JobsSignedOff: no job-signing key is pinned; jobs are not verified.
	JobsSignedOff = "off"
)

// RequireSignedJobsFromEnv reads EnvRequireSignedJobs: set reports whether
// it is set; an unrecognized value is an error.
func RequireSignedJobsFromEnv(lookup func(string) (string, bool)) (required, set bool, err error) {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	v, ok := lookup(EnvRequireSignedJobs)
	if v = strings.TrimSpace(v); !ok || v == "" {
		return false, false, nil
	}
	b, perr := strconv.ParseBool(v)
	if perr != nil {
		return false, false, fmt.Errorf("%s=%q is not recognized: set it to true (refuse commands without a valid job signature) or false", EnvRequireSignedJobs, v)
	}
	return b, true, nil
}

// JobGuard decides whether a claimed command may run as far as its job
// signature goes. Build it with NewJobGuard and give it to the poller
// (CommandPoller.SetJobGuard).
type JobGuard struct {
	v        *jobsig.Verifier
	required bool
	tenantID string
	sensorID string

	// cv follows the platform's config_version (SetConfigVersion); a
	// pointer keeps JobGuard comparable.
	cv *configVersionWatch
}

// configVersionWatch is the config_version the key set was last fetched
// under.
type configVersionWatch struct {
	current func() string
	mu      sync.Mutex
	last    string
}

// SetConfigVersion gives the guard the platform's current config_version
// (Doorbell.ConfigVersion). A new job-signing key set changes it, and the
// guard then fetches the key set again before it checks the next command,
// so a rotated or revoked signer key takes effect without a restart.
func (g *JobGuard) SetConfigVersion(f func() string) {
	if g != nil && f != nil {
		g.cv = &configVersionWatch{current: f}
	}
}

// refreshKeySet fetches the key set again when config_version moved.
func (g *JobGuard) refreshKeySet(ctx context.Context) {
	ks := g.v.KeySet()
	if ks == nil || g.cv == nil {
		return
	}
	cv := g.cv.current()
	g.cv.mu.Lock()
	changed := cv != "" && cv != g.cv.last
	if changed {
		g.cv.last = cv
	}
	g.cv.mu.Unlock()
	if changed {
		_ = ks.Refresh(ctx, true)
	}
}

// NewJobGuard returns a guard for this sensor (tenantID, sensorID) that
// verifies with v (nil: no key pinned) and, when required, refuses
// commands without a valid signature. A guard that verifies needs both
// ids; a required guard needs a verifier.
func NewJobGuard(v *jobsig.Verifier, required bool, tenantID, sensorID string) (*JobGuard, error) {
	if required && v == nil {
		return nil, fmt.Errorf("signed jobs are required (%s) but no job-signing key or root is pinned: set SENSOR_JOB_SIGNING_ROOT or SENSOR_JOB_SIGNING_KEYS, or pair the sensor again", EnvRequireSignedJobs)
	}
	if v != nil && (tenantID == "" || sensorID == "") {
		return nil, errors.New("signed jobs need the sensor's own organization and sensor id: verify them on a paired (key-bound) sensor")
	}
	return &JobGuard{v: v, required: required, tenantID: tenantID, sensorID: sensorID}, nil
}

// Posture is the guard's JobsSigned* posture.
func (g *JobGuard) Posture() string {
	switch {
	case g == nil || g.v == nil:
		return JobsSignedOff
	case g.required:
		return JobsSignedRequired
	}
	return JobsSignedVerifiedWhenPresent
}

// verifies reports whether the guard checks signatures (a key is pinned).
func (g *JobGuard) verifies() bool { return g != nil && g.v != nil }

// Check verifies cmd's signed job. nil: the command may run. A refusal is a
// *LocalPolicyError (layer builtin, rule job_signature).
func (g *JobGuard) Check(ctx context.Context, cmd *Command) error {
	if g == nil {
		return nil
	}
	unsigned := len(bytes.TrimSpace(cmd.SignedJob)) == 0 || bytes.Equal(bytes.TrimSpace(cmd.SignedJob), []byte("null"))
	switch {
	case unsigned && g.required:
		return jobRefusal("the command is not signed and this sensor requires signed jobs")
	case unsigned, g.v == nil:
		// Legacy: unsigned commands run; without a pinned key a signature
		// cannot be checked.
		return nil
	}
	g.refreshKeySet(ctx)
	_, err := g.v.Verify(ctx, cmd.SignedJob, jobsig.Binding{
		TenantID: g.tenantID, SensorID: g.sensorID, CommandID: cmd.ID, CommandType: cmd.Type,
		LeaseEpoch: cmd.LeaseEpoch, Payload: cmd.Payload,
	})
	if err != nil {
		if jobsig.ReasonOf(err) == jobsig.ReasonKeySet {
			return &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleJobKeySet, Detail: err.Error()}
		}
		return jobRefusal(err.Error())
	}
	return nil
}

func jobRefusal(detail string) error {
	return &LocalPolicyError{Layer: RefusalLayerBuiltin, Rule: RefusalRuleJobSignature, Detail: detail}
}

// CommandClaimer claims a command and returns it as the claim answered it:
// its payload, its signed job and the lease epoch of the claim.
// *client.Client implements it. With a JobGuard that verifies, the poller
// claims through it, so the signed job and the payload it checks are the
// claim's.
type CommandClaimer interface {
	ClaimCommand(ctx context.Context, id string) (*Command, error)
}

// jobsPosture is the posture CurrentPosture reports (SetJobsPosture).
var jobsPosture atomic.Pointer[string]

// jobsKeySet is the key set trust CurrentPosture reports (SetJobsKeySet).
var jobsKeySet atomic.Pointer[jobsig.KeySetTrust]

// SetJobsKeySet sets the key set trust whose root, version and expiry
// CurrentPosture reports; nil reports none.
func SetJobsKeySet(t *jobsig.KeySetTrust) { jobsKeySet.Store(t) }

// SetJobsPosture sets the JobsSigned* posture CurrentPosture reports; ""
// reports none.
func SetJobsPosture(signed string) {
	if signed == "" {
		jobsPosture.Store(nil)
		return
	}
	jobsPosture.Store(&signed)
}
