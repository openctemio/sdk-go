package core

// The sensor's security posture (api RFC-040, docs/rfcs/RFC-040-platform-
// sensor-mutual-distrust.md in openctemio/openctem): how the sensor
// authenticates the platform's TLS certificate and how its tool runs are
// confined. The manifest carries it (member "posture") to a platform that
// lists the "posture" feature, so the platform can flag sensors that run
// unhardened. It only reports; nothing the platform answers changes it. The
// local policy's own posture (state, required) is in "local_policy".

import (
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// Platform TLS pins, as PlatformTLSPosture.Pin reports them.
const (
	// TLSPinFingerprint: platform requests trust only a pinned TLS
	// identity: the CA certificate of SENSOR_CA_FINGERPRINT, or the trust
	// anchor key recorded at pairing (identity.json platform_tls_pin).
	TLSPinFingerprint = "fingerprint"
	// TLSPinCAFile: platform requests trust a private CA file
	// (SENSOR_CA_CERT_FILE) besides the system trust store.
	TLSPinCAFile = "ca_file"
	// TLSPinNone: platform requests trust the system trust store only.
	TLSPinNone = "none"
)

// SensorPosture is the manifest member "posture".
type SensorPosture struct {
	// PlatformTLS is how platform requests over HTTPS check the platform's
	// certificate.
	PlatformTLS *PlatformTLSPosture `json:"platform_tls,omitempty"`
	// Sandbox is how tool runs are confined.
	Sandbox *SandboxPosture `json:"sandbox,omitempty"`
	// Jobs is how the sensor checks the platform's job signatures; nil
	// when the runtime did not decide it (SetJobsPosture).
	Jobs *JobsPosture `json:"jobs,omitempty"`
}

// JobsPosture is the sensor's signed-job checking (api RFC-040 §5.6).
type JobsPosture struct {
	// Signed is JobsSignedRequired, JobsSignedVerifiedWhenPresent or
	// JobsSignedOff.
	Signed string `json:"signed"`
	// Root is the pinned job-signing root key id; "" when none is pinned.
	Root string `json:"root,omitempty"`
	// KeySetVersion and KeySetExpiresAt describe the accepted key set of
	// the pinned root (absent without one): the sensor refuses every signed
	// job once it expires, until the platform deploys a new one.
	KeySetVersion   uint64     `json:"keyset_version,omitempty"`
	KeySetExpiresAt *time.Time `json:"keyset_expires_at,omitempty"`
}

// PlatformTLSPosture is the platform TLS pin of the sensor's HTTPS
// requests (the gRPC transport always pins its own CA bundle, which it
// fetches over these requests).
type PlatformTLSPosture struct {
	// Pin is TLSPinFingerprint, TLSPinCAFile or TLSPinNone.
	Pin string `json:"pin"`
}

// SandboxPosture is the tool sandbox's protection (executor.Status).
type SandboxPosture struct {
	// Mode is the sandbox mode: off, auto or required (SENSOR_SANDBOX).
	Mode string `json:"mode"`
	// Sandboxed is true when tool runs go through the sandbox launcher.
	Sandboxed bool `json:"sandboxed"`
	// NetworkEnforced is true when each tool run's network is confined to
	// its own forwarder (SENSOR_SANDBOX_NETWORK); false means the target
	// checks are the only control on where a tool connects.
	NetworkEnforced bool `json:"network_enforced"`
}

// PlatformTLSPin is the platform TLS pin of API clients created now:
// TLSPinFingerprint when a CA fingerprint or an anchor key is pinned
// (httpsec.SetAPIPinnedCA, httpsec.SetAPIPinnedSPKI), TLSPinCAFile when
// only a private CA pool is set (httpsec.SetAPIRootCAs), else TLSPinNone.
func PlatformTLSPin() string {
	switch {
	case httpsec.HasAPIPin():
		return TLSPinFingerprint
	case httpsec.APIRootCAs() != nil:
		return TLSPinCAFile
	}
	return TLSPinNone
}

// CurrentPosture is the posture now: the platform TLS pin, the status of
// the tool sandbox installed with executor.SetCurrent and the signed-job
// checking set with SetJobsPosture.
func CurrentPosture() *SensorPosture {
	st := executor.Current().Status()
	p := &SensorPosture{
		PlatformTLS: &PlatformTLSPosture{Pin: PlatformTLSPin()},
		Sandbox:     &SandboxPosture{Mode: string(st.Mode), Sandboxed: st.Sandboxed, NetworkEnforced: st.NetworkEnforced},
	}
	if s := jobsPosture.Load(); s != nil {
		p.Jobs = &JobsPosture{Signed: *s}
		if t := jobsKeySet.Load(); t != nil {
			p.Jobs.Root = t.Root()
			if ks := t.Current(); ks != nil {
				exp := ks.NotAfter.UTC()
				p.Jobs.KeySetVersion, p.Jobs.KeySetExpiresAt = ks.Version, &exp
			}
		}
	}
	return p
}
