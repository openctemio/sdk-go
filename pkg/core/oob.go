package core

// Out-of-band interactions (OOB: a target calls back to an interaction
// server, which shows a blind effect such as SSRF or a JNDI lookup). A job
// asks for them with the config key "allow_interactsh"; a scanner that can
// use them (nuclei) uses them only with an interaction server the sensor is
// configured with, never a public default, and a scan that cannot use them
// runs without them and says why (ScanResult.OOB) instead of failing.

// MetaOOB is the result metadata key of a scan's out-of-band state
// (*OOBState), set when the job asked for out-of-band callbacks.
const MetaOOB = "oob"

// States of OOBState.
const (
	// OOBOn: the scan ran with out-of-band callbacks.
	OOBOn = "on"
	// OOBUnavailable: the job asked for them and the scan ran without
	// them (OOBState.Reason says why): its templates that need a callback
	// did not run, which is a coverage gap, not "nothing found".
	OOBUnavailable = "unavailable"
)

// Reasons of an unavailable OOBState.
const (
	// OOBReasonNoServer: the sensor has no interaction server configured.
	OOBReasonNoServer = "no_server"
	// OOBReasonLocalPolicy: the sensor's local policy sets
	// allow_interactsh: false, or the sensor requires a local policy and
	// has none.
	OOBReasonLocalPolicy = "local_policy"
	// OOBReasonUnconfined: the server needs a token and the sensor does not
	// confine the tool's network, so the token would have to be handed to
	// the tool (and its command line).
	OOBReasonUnconfined = "requires_confined_sensor"
	// OOBReasonRegistration: the tool could not register with the server.
	OOBReasonRegistration = "registration_failed"
	// OOBReasonDisabled: the sensor's operator turned callbacks off for the
	// scanner.
	OOBReasonDisabled = "disabled_on_sensor"
)

// OOBState is what a scan did with the out-of-band callbacks its job asked
// for.
type OOBState struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
	// Detail is a short operator-facing explanation (no secrets).
	Detail string `json:"detail,omitempty"`
}

// OOBMetadata returns the result metadata for r's out-of-band state (empty
// when the job did not ask for callbacks).
func OOBMetadata(r *ScanResult) map[string]any {
	if r == nil || r.OOB == nil || r.OOB.State == "" {
		return map[string]any{}
	}
	s := *r.OOB
	return map[string]any{MetaOOB: &s}
}

// oobDetails are the operator-facing explanations of the reasons.
var oobDetails = map[string]string{
	OOBReasonNoServer:     "the job asks for out-of-band callbacks and this sensor has no interaction server configured; templates that need a callback did not run",
	OOBReasonLocalPolicy:  "the sensor's local policy turns out-of-band callbacks off; templates that need a callback did not run",
	OOBReasonUnconfined:   "the interaction server needs a token and this sensor does not confine the tool's network, so the token is never handed to the tool; templates that need a callback did not run",
	OOBReasonRegistration: "the tool could not register with the interaction server; templates that need a callback found nothing they could confirm",
	OOBReasonDisabled:     "the sensor's operator turned out-of-band callbacks off for this scanner; templates that need a callback did not run",
}

// OOBOffState is the unavailable state for reason, with its explanation.
func OOBOffState(reason string) *OOBState {
	return &OOBState{State: OOBUnavailable, Reason: reason, Detail: oobDetails[reason]}
}
