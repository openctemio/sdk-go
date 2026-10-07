package toolhost

import (
	"encoding/json"
	"fmt"

	"github.com/openctemio/ctis/capability"
	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// RatePolicy is a Policy that also caps a tool's request rate (the
// sensor-local policy's rate.max_rps). A Policy without it leaves the rate
// as the task set it.
type RatePolicy interface {
	CapRate(requested int) int
}

// maxContractLogs bounds the violations an Outcome lists in its logs.
const maxContractLogs = 10

// admitContract applies the tool contract to a task before anything
// starts: the job's tier ceiling against the tool's minimum tier, and the
// capability's standard params mapped onto the tool's config keys.
func admitContract(m tool.Manifest, task tool.Task) (tool.Task, *tool.Error) {
	if task.MaxTier != "" && m.MinimumTier().Exceeds(task.MaxTier) {
		return task, refusedErr("%s needs tier %s; the job allows at most %s", m.Name, m.MinimumTier(), task.MaxTier)
	}
	if werr := toolrt.CheckWebScope(m, task); werr != nil {
		return task, werr
	}
	mapped, err := m.ApplyParams(task)
	if err != nil {
		return task, tool.AsError(err)
	}
	return mapped, nil
}

// capRate lowers the tool's rate key (safety.rate_param) to what the
// policy allows, and sets it when the task left it unset and the policy has
// a maximum. It returns a log line when it changed the rate.
func capRate(m tool.Manifest, cfg json.RawMessage, pol Policy) (json.RawMessage, *LogLine, error) {
	rp, ok := pol.(RatePolicy)
	if !ok || m.Safety == nil || m.Safety.RateParam == "" {
		return cfg, nil, nil
	}
	values := map[string]any{}
	if len(cfg) > 0 {
		if err := json.Unmarshal(cfg, &values); err != nil {
			return nil, nil, err
		}
	}
	key := m.Safety.RateParam
	requested := 0
	if f, ok := values[key].(float64); ok && f > 0 {
		requested = int(f)
	}
	capped := rp.CapRate(requested)
	if capped == requested || capped <= 0 {
		return cfg, nil, nil
	}
	values[key] = capped
	out, err := json.Marshal(values)
	if err != nil {
		return nil, nil, err
	}
	line := &LogLine{Level: "info", Msg: fmt.Sprintf("the local policy set %s to %d (asked %d)", key, capped, requested),
		Fields: map[string]any{"source": "runtime", "rate_param": key, "requested": requested, "capped": capped}}
	return out, line, nil
}

// checkContract checks the accepted output against the task capability's
// contract (capability.Capability.Check, with the tool's output shape).
// Violations are logged and make an ok task partial; the records are
// delivered, and the platform checks them again.
func (p *prepared) checkContract(out *Outcome) {
	if p.task.Capability == "" || out.Report == nil {
		return
	}
	c, ok := capability.Lookup(p.task.Capability)
	if !ok {
		return
	}
	im, _ := p.m.Implementation(p.task.Capability)
	violations, err := c.Check(out.Report, capability.CheckOptions{Shape: im.OutputShape})
	if err != nil || len(violations) == 0 {
		return
	}
	out.Stats.ContractViolations = len(violations)
	shown := make([]string, 0, min(len(violations), maxContractLogs))
	for _, v := range violations[:min(len(violations), maxContractLogs)] {
		shown = append(shown, v.String())
	}
	out.Logs = append(out.Logs, LogLine{Level: "warn",
		Msg:    fmt.Sprintf("%d record(s) miss the contract of %s", len(violations), c.Ref()),
		Fields: map[string]any{"source": "runtime", "capability": c.Ref(), "violations": shown}})
	if out.Status == tool.StatusOK {
		out.Status = tool.StatusPartial
	}
}
