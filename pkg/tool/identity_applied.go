package tool

import (
	"regexp"
	"strings"
)

// Where an applied identification value came from.
const (
	// SourceJob: the signed job's http_policy (the platform's and the
	// organization's layers, merged by the platform).
	SourceJob = "job"
	// SourceJobLocked: a job value the platform enforces or a program sets;
	// the sensor-local layer cannot change it.
	SourceJobLocked = "job_locked"
	// SourceSensor: the sensor owner's local policy (http.headers,
	// http.user_agent).
	SourceSensor = "sensor"
)

// AppliedIdentity is the identification a task's requests actually carry,
// as the sensor reports it with the result so the platform can show what a
// scan was sent with. Values of secret-looking names are masked
// (MaskIdentityValue); an entry that was not applied says why.
type AppliedIdentity struct {
	Tool            string          `json:"tool"`
	UserAgent       string          `json:"user_agent,omitempty"`
	UserAgentSource string          `json:"user_agent_source,omitempty"`
	Headers         []AppliedHeader `json:"headers,omitempty"`
	Query           *AppliedQuery   `json:"query,omitempty"`
	// UserAgentPool is the length of the rotation list in force (0: one
	// User-Agent, no rotation). UserAgent is then the value of the task's
	// first target host; each host gets its own (contract
	// identity.SelectUserAgent with the job's key).
	UserAgentPool int `json:"user_agent_pool,omitempty"`
	// UserAgentReason says why requests may not carry UserAgent as
	// reported: the tool cannot set one, or takes one per process while
	// the task's hosts get different values.
	UserAgentReason string `json:"user_agent_reason,omitempty"`
	// Required: the job requires identification; every request to a
	// target carried the headers and the query parameter (the task would
	// have been refused otherwise).
	Required bool `json:"required,omitempty"`
	// Carrier is who put the identification on the requests: CarrierTool
	// (the tool's own flags or the SDK HTTP client) or CarrierForwarder
	// (the task's forwarder, on every request, for a tool that cannot).
	Carrier string `json:"carrier,omitempty"`
}

// Carriers of the identification.
const (
	CarrierTool      = "tool"
	CarrierForwarder = "forwarder"
)

// AppliedHeader is one header of the applied identification.
type AppliedHeader struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Source string `json:"source"`
	// Applied is false for a header that was not sent: a sensor-local
	// header whose name the job locks.
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// AppliedQuery is the task's query parameter and whether the tool carried it.
type AppliedQuery struct {
	Name    string `json:"name"`
	Value   string `json:"value"`
	Applied bool   `json:"applied"`
	Reason  string `json:"reason,omitempty"`
}

// Masked is what MaskIdentityValue puts in place of a secret value.
const Masked = "****"

var identitySecretNameRE = regexp.MustCompile(`(?i)(token|secret|key|pass|auth|cred|session|signature|cookie|bearer)`)

// MaskIdentityValue hides the value of a header or parameter whose name
// looks like a secret. Validation already refuses credential headers, so
// this is the second line: a report never carries a secret.
func MaskIdentityValue(name, value string) string {
	if value != "" && identitySecretNameRE.MatchString(strings.TrimSpace(name)) {
		return Masked
	}
	return value
}
