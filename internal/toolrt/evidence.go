package toolrt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
