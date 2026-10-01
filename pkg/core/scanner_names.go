package core

import "strings"

// ScannerBetterleaks is the name of the secret scanner (betterleaks), as the
// sensor reports it in CTIS tool.name and as the platform dispatches it.
const ScannerBetterleaks = "betterleaks"

// retiredScanners maps the name of a scanner that was replaced to the name
// of its replacement. Betterleaks replaced gitleaks: it is the drop-in
// successor by gitleaks' original author, reads gitleaks configs and writes
// the gitleaks JSON report format.
//
// This is the SDK's only mapping of old scanner names. It exists so that a
// command or a custom template a platform still sends under the old name
// (an API that has not migrated its scan configs yet) runs on the
// replacement instead of failing with "scanner not found".
var retiredScanners = map[string]string{
	"gitleaks": ScannerBetterleaks,
}

// CanonicalScannerName returns the current name for a scanner or template
// type: a retired name maps to its replacement, anything else is returned
// unchanged.
func CanonicalScannerName(name string) string {
	if to, ok := retiredScanners[strings.ToLower(strings.TrimSpace(name))]; ok {
		return to
	}
	return name
}
