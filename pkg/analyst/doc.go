// Package analyst is the AI analyst harness: the loop an analyst worker (a
// sensor in the analyst role) runs for one openctem.analyze/v1 job.
//
// One run = one job of one organization. The platform decides everything
// that bounds the run before the model reads a byte: the signed grant (tools,
// target placeholders, tier ceiling, budgets), the masked context bundle, the
// playbook and the closed output schema. The harness then loops: call the
// model, decide every requested tool call (grant policy, input schema, bound
// targets, hooks, budget), run the allowed calls in parallel, fence their
// output as untrusted data, and finish with an answer that must satisfy the
// output schema and cite only evidence that exists. Everything is written to
// an append-only run record that a replay or an eval reads back.
//
// What the harness never does: hold platform credentials beyond the job,
// reach a target that is not bound in the grant (the egress forwarder
// enforces the same rule at the network layer), run an intrusive tool, keep
// memory between jobs or organizations, or apply anything: the platform
// turns the result into the analyst's normal commands, with approvals.
//
// Design: openctem api/docs/rfcs/RFC-133-ai-analyst-harness.md.
//
// Stability: Experimental (docs/STABILITY.md).
package analyst
