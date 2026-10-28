package harness

import (
	"encoding/json"
)

// DefaultMaxProviderStateBytes caps Message.ProviderState per message.
const DefaultMaxProviderStateBytes = 64 << 10

// ProviderState handling.
//
// The state is opaque to the harness and owned by one provider: it is kept in
// the run record (the model_response event carries the whole message) so a
// resume can send thinking blocks and signatures back.
//
// Digest decision: the state is part of the request digest and of the record
// digest. It is part of what the provider receives, so leaving it out would let
// a record be edited without the digest noticing. This does not make replay
// non-deterministic: a replay answers from the recorded responses, which carry
// the recorded state verbatim, so the same record gives the same digests.
// Dropping the state on a provider change (a fallback) does change the request
// digest, on purpose: that request differs.
//
// Isolation: state produced by one provider is never sent to another. The
// harness stamps every response with the provider's name (an adapter cannot
// stamp for another provider) and removes state whose stamp is not the current
// provider's. Signatures are a provider's private material, and another vendor
// must not see them.

func (r *Run) maxState() int {
	if r.MaxProviderStateBytes > 0 {
		return r.MaxProviderStateBytes
	}
	return DefaultMaxProviderStateBytes
}

// usableState reports whether the state may be kept: valid JSON within the cap.
func (r *Run) usableState(s json.RawMessage) bool {
	return len(s) > 0 && len(s) <= r.maxState() && json.Valid(s)
}

// stampState normalizes a model response message: the assistant role, and
// ProviderState kept only when valid and within the cap, stamped with this
// run's provider.
func (st *runState) stampState(m Message) Message {
	m.Role = RoleAssistant
	m.StateProvider = ""
	if !st.r.usableState(m.ProviderState) {
		m.ProviderState = nil
		return m
	}
	m.StateProvider = st.r.Provider.Name()
	return m
}

// sanitizeResume returns the resumed turns with ProviderState removed unless
// it is an assistant turn stamped by this run's provider, valid and within the cap.
func (st *runState) sanitizeResume(in []Message) []Message {
	out := make([]Message, 0, len(in))
	for _, m := range in {
		keep := m.Role == RoleAssistant && m.StateProvider == st.r.Provider.Name() && st.r.usableState(m.ProviderState)
		if !keep {
			m.ProviderState, m.StateProvider = nil, ""
		}
		out = append(out, m)
	}
	return out
}
