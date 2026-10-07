package conformance

import (
	"fmt"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// evidenceProblems checks the evidence items of a report's findings: the
// CTIS shape and caps, and that every sensitive header value of an HTTP
// exchange (Authorization, Cookie, Set-Cookie, API keys) is marked in the
// item's sensitive spans, so the platform masks it.
func evidenceProblems(rep *ctis.Report) []string {
	if rep == nil {
		return nil
	}
	var out []string
	for i, f := range rep.Findings {
		if len(f.EvidenceItems) == 0 {
			continue
		}
		if err := toolrt.CheckEvidenceItems(f.EvidenceItems); err != nil {
			out = append(out, fmt.Sprintf("finding %d: %v", i, err))
			continue
		}
		for j, it := range f.EvidenceItems {
			if it.Kind != ctis.EvidenceKindHTTPExchange || it.HTTP == nil {
				continue
			}
			check := func(part string, hs []ctis.EvidenceHeader) {
				for k, h := range hs {
					ptr := fmt.Sprintf("/http/%s/headers/%d/value", part, k)
					if h.Value != "" && ctis.IsSensitiveHeader(h.Name) && !marked(it, ptr) {
						out = append(out, fmt.Sprintf("finding %d evidence %d: the %s header value is not marked sensitive (%s)", i, j, h.Name, ptr))
					}
				}
			}
			if it.HTTP.Request != nil {
				check("request", it.HTTP.Request.Headers)
			}
			if it.HTTP.Response != nil {
				check("response", it.HTTP.Response.Headers)
			}
		}
	}
	return out
}

func marked(it ctis.EvidenceItem, ptr string) bool {
	for _, s := range it.Sensitive {
		if s.Pointer == ptr {
			return true
		}
	}
	return false
}
