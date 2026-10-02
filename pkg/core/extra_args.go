package core

import (
	"fmt"
	"strings"
)

// DangerousToolFlags are scanner CLI flags that must never arrive through
// ScanOptions.ExtraArgs or ReconOptions.ExtraArgs. Extra args can come from a
// job payload, so each of these would let whoever controls the payload change
// what the tool talks to or executes (CWE-77): write files, route traffic
// through their proxy (SSRF/MITM), name targets that skipped target
// validation, load their own templates or rules (nuclei code: protocol = RCE),
// call back to their interaction server, run a headless browser, use their
// DNS resolvers, or bind to another interface or source address.
//
// The sensor's platform-mode executor enforced this set until that mode was
// removed (sensor#107); it now lives here so every SDK scanner applies it.
var DangerousToolFlags = map[string]bool{
	// File output / report redirection
	"-o": true, "--output": true,
	"-oa": true, "-on": true, "-ox": true, "-og": true, "-oj": true,
	"--report-db": true,

	// HTTP proxy: MITM or SSRF through an attacker proxy
	"-proxy": true, "--proxy": true, "-http-proxy": true,

	// Target-list file (bypasses target validation of the payload)
	"-il": true, "--input-list": true,

	// Flags that name a target or a target file. Targets come only from the
	// validated payload; a target-bearing extra arg would bypass the SSRF
	// guard (nuclei -u/-l, httpx -u/-l, katana -u/-list, subfinder -d/-dL,
	// dnsx -d/-l, naabu -host/-l).
	"-u": true, "--u": true, "-url": true, "--url": true,
	"-target": true, "--target": true, "-targets": true, "--targets": true,
	"-l": true, "--l": true, "-list": true, "--list": true,
	"-d": true, "--d": true, "-dl": true, "--dl": true, "-domain": true, "--domain": true,
	"-host": true, "--host": true, "-hl": true,

	// Custom rule / template paths (nuclei -t, semgrep --config,
	// betterleaks --config): attacker rules = attacker-controlled behaviour.
	"-c": true, "--config": true,
	"-t": true, "--templates": true,

	// Out-of-band interaction / callback server
	"-iserver": true, "--interactsh-url": true,

	// Headless browser (arbitrary JS execution / file system access)
	"--headless": true,

	// Custom DNS resolvers (exfiltration of enumeration data)
	"-r": true, "--resolvers": true,

	// Network-level flags on recon tools
	"-interface": true, "--interface": true,
	"-source-ip": true, "--source-ip": true,
}

// ValidateExtraArgs rejects extra CLI args that contain a DangerousToolFlags
// entry, either bare ("-proxy") or in "flag=value" form ("-proxy=http://x").
// Matching is case-insensitive and ignores surrounding whitespace.
func ValidateExtraArgs(args []string) error {
	for _, arg := range args {
		lower := strings.ToLower(strings.TrimSpace(arg))
		if DangerousToolFlags[lower] {
			return fmt.Errorf("extra arg %q is not allowed", arg)
		}
		if i := strings.IndexByte(lower, '='); i > 0 && DangerousToolFlags[lower[:i]] {
			return fmt.Errorf("extra arg %q is not allowed", arg)
		}
	}
	return nil
}
