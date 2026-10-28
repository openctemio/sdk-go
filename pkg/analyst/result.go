package analyst

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/analyst/contract"
)

type wireUsage struct {
	Provider  string `json:"provider"`
	Model     string `json:"model"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	Steps     int    `json:"steps,omitempty"`
	ToolCalls int    `json:"tool_calls,omitempty"`
}

type wireTemplate struct {
	ID       string `json:"id"`
	Digest   string `json:"digest"`
	External bool   `json:"external,omitempty"`
}

type wireRecord struct {
	Digest    string `json:"digest"`
	UploadRef string `json:"upload_ref,omitempty"`
}

type wireResult struct {
	Contract    string                `json:"contract"`
	JobID       string                `json:"job_id"`
	Status      Status                `json:"status"`
	ErrorCode   string                `json:"error_code,omitempty"`
	Suggestions []contract.Suggestion `json:"suggestions"`
	Usage       wireUsage             `json:"usage"`
	Template    wireTemplate          `json:"template"`
	RunRecord   *wireRecord           `json:"run_record,omitempty"`
}

// ContractResult renders the run as an openctem.analyze.result/v1 document,
// validated against the schema before it leaves the worker. external marks a
// playbook the platform did not name (a third-party agent's own prompts).
func (r Result) ContractResult(jobID string, in Instructions, external bool) ([]byte, error) {
	w := wireResult{
		Contract: contract.Result, JobID: jobID, Status: r.Status, ErrorCode: r.ErrorCode,
		Suggestions: []contract.Suggestion{},
		Usage: wireUsage{Provider: r.Provider, Model: r.Model, TokensIn: r.Usage.TokensIn, TokensOut: r.Usage.TokensOut,
			Steps: r.Usage.Steps, ToolCalls: r.Usage.ToolCalls},
		Template: wireTemplate{ID: in.ID, Digest: in.Digest, External: external},
	}
	if r.Output != nil && r.Status == StatusCompleted {
		w.Suggestions = r.Output.Suggestions
	}
	if r.RecordDigest != "" {
		w.RunRecord = &wireRecord{Digest: r.RecordDigest}
	}
	b, err := json.Marshal(w)
	if err != nil {
		return nil, err
	}
	if err := contract.Validate(contract.SchemaResult, b); err != nil {
		return nil, err
	}
	return b, nil
}
