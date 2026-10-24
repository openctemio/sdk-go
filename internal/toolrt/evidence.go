package toolrt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// maxTemplateDigest bounds a verdict's template digest.
const maxTemplateDigest = 128

// checkVerdictEvidence checks a verdict's evidence and template digest as
// CTIS checks a finding's evidence_items: the count, each item's size and
// shape. The platform checks them again.
func checkVerdictEvidence(r tool.VerdictReport) error {
	if len(r.TemplateDigest) > maxTemplateDigest || strings.ContainsFunc(r.TemplateDigest, func(c rune) bool { return c < 0x21 || c == 0x7f }) {
		return errors.New("unreadable template digest")
	}
	if len(r.Evidence) == 0 {
		return nil
	}
	if len(r.Evidence) > tool.MaxVerdictEvidence {
		return fmt.Errorf("%d evidence items, at most %d", len(r.Evidence), tool.MaxVerdictEvidence)
	}
	return CheckEvidenceItems(r.Evidence)
}

// CheckEvidenceItems validates evidence items with the CTIS rules (kind,
// caps, the shape of known kinds), by validating a minimal report that
// carries them.
func CheckEvidenceItems(items []ctis.EvidenceItem) error {
	for i := range items {
		b, err := json.Marshal(items[i])
		if err != nil {
			return fmt.Errorf("evidence %d: %w", i, err)
		}
		if len(b) > ctis.MaxEvidenceItemBytes {
			return fmt.Errorf("evidence %d: %d bytes, at most %d", i, len(b), ctis.MaxEvidenceItemBytes)
		}
	}
	rep := ctis.NewReport()
	rep.Assets = []ctis.Asset{{ID: "a", Type: ctis.AssetTypeDomain, Value: "evidence.invalid"}}
	rep.Findings = []ctis.Finding{{Type: ctis.FindingTypeVulnerability, Title: "evidence", Severity: ctis.SeverityInfo,
		AssetRef: "a", EvidenceItems: items}}
	if err := rep.Validate(); err != nil {
		return fmt.Errorf("evidence: %w", err)
	}
	return nil
}

// hasAnsweredExchange reports whether the evidence holds an http_exchange
// whose response arrived.
func hasAnsweredExchange(items []ctis.EvidenceItem) bool {
	for _, it := range items {
		if it.Kind == ctis.EvidenceKindHTTPExchange && it.HTTP != nil && it.HTTP.Response != nil && it.HTTP.Response.Status > 0 {
			return true
		}
	}
	return false
}

// cleanRequests keeps at most tool.MaxVerdictRequests request results with
// printable, bounded text: the tool's output is hostile until checked. A
// result without a URL is dropped.
func cleanRequests(in []tool.RequestResult) []tool.RequestResult {
	if len(in) == 0 {
		return nil
	}
	out := make([]tool.RequestResult, 0, min(len(in), tool.MaxVerdictRequests))
	for _, r := range in {
		if len(out) == tool.MaxVerdictRequests {
			break
		}
		u := cleanURL(r.URL)
		if u == "" || len(u) > tool.MaxRequestURL {
			continue
		}
		if r.Status < 0 || r.Status > 999 {
			r.Status = 0
		}
		out = append(out, tool.RequestResult{URL: u, Status: r.Status, Matched: r.Matched,
			Error: tool.CapDetail(CleanString(r.Error)), EdgeVendor: shortToken(r.EdgeVendor), EdgeState: shortToken(r.EdgeState)})
	}
	return out
}

// shortToken is a lowercase identifier of at most 32 bytes ("" when it
// holds anything else).
func shortToken(s string) string {
	if len(s) > 32 {
		return ""
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return ""
		}
	}
	return s
}

// cleanURL drops whitespace and control characters: a URL has none.
func cleanURL(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return -1
		}
		return r
	}, CleanString(s))
}
