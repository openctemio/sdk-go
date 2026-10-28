package playbook

import (
	"context"
	"fmt"

	"github.com/openctemio/sdk-go/pkg/harness"
	"github.com/openctemio/sdk-go/pkg/harness/contract"
)

// CodeMissingEvidence is the refusal code of an answer that skips a required
// bundle field.
const CodeMissingEvidence = "missing_required_evidence"

func requireEvidence(required []string) harness.Verifier {
	return func(_ context.Context, _ harness.Job, out *contract.Output, refs map[string]bool) error {
		for i, s := range out.Suggestions {
			if s.Kind != "verdict" {
				continue
			}
			cited := map[string]bool{}
			for _, e := range s.Evidence {
				cited[e.Ref] = true
			}
			for _, r := range required {
				// A field the bundle does not carry (withheld by the data
				// class) cannot be cited and is not required.
				if refs[r] && !cited[r] {
					return &harness.VerifyError{Code: CodeMissingEvidence, Location: fmt.Sprintf("/suggestions/%d/evidence", i)}
				}
			}
		}
		return nil
	}
}
