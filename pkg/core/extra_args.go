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
	// betterleaks --config): attacker rules = attacker-controlled behavior.
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

	// Command execution: naabu runs the -nmap-cli string as a command.
	"-nmap-cli": true, "-nmap": true,

	// More file output (nuclei/httpx/katana/subfinder exports and stored
	// responses; semgrep's per-format outputs).
	"-json-export": true, "-je": true, "-jsonl-export": true, "-jle": true,
	"-markdown-export": true, "-me": true, "-sarif-export": true, "-se": true,
	"-store-resp": true, "-sresp": true, "-store-resp-dir": true, "-srd": true,
	"-store-response": true, "-sr": true, "-store-response-dir": true,
	"-output-dir": true, "-od": true, "-report-config": true, "-rc": true,
	"-trace-log": true, "-tlog": true, "-error-log": true, "-elog": true,
	"--sarif-output": true, "--json-output": true, "--text-output": true,
	"--junit-xml-output": true, "--gitlab-sast-output": true,
	"--gitlab-secrets-output": true, "--emacs-output": true, "--vim-output": true,

	// More template / rule / config sources (remote templates and
	// workflows, code protocol, local file access, env vars handed to
	// templates, tool config files, provider credentials).
	"-config": true, "-f": true,
	"-tu": true, "-template-url": true, "-w": true, "-workflows": true,
	"-wu": true, "-workflow-url": true, "-code": true,
	"-lfa": true, "-allow-local-file-access": true,
	"-ev": true, "-env-vars": true,
	"-pc": true, "-provider-config": true, "-secret-file": true, "-sf": true,

	// More proxy / DNS / browser flags.
	"-proxy-auth": true, "-resolver": true, "-rlist": true,
	"-system-resolvers": true, "-system-chrome": true, "-system-chrome-path": true,
	"-chrome-data-dir": true, "-cdd": true, "-screenshot": true, "-ss": true,
	"-show-browser": true, "-sb": true, "-iserver-token": true, "-itoken": true,

	// Template trust (nuclei v3.11 -h, TEMPLATES section). The sensor
	// decides which template types may load: never the code protocol, file
	// templates, self-contained templates or the headless browser, and it
	// always runs the official templates with -disable-unsigned-templates.
	// "-dut=false" would switch that check off, so -dut is refused too.
	"-file": true, "-esc": true, "-enable-self-contained": true,
	"-egm": true, "-enable-global-matchers": true,
	"-dut": true, "-disable-unsigned-templates": true,
	"-sign": true, "-headless": true,
	"-ho": true, "-headless-options": true, "-cdpe": true, "-cdp-endpoint": true,
	"-sc": true, "-dast": true, "-fuzz": true,
	// Template sources by their nuclei short names (-turl/-wurl; -tu/-wu
	// above are older spellings), AI-generated templates, template profiles
	// (a profile file can turn on code/headless) and templates forced past
	// the filters.
	"-turl": true, "-wurl": true, "-ai": true, "-prompt": true,
	"-tp": true, "-profile": true, "-it": true, "-include-templates": true,
	"-vfp": true, "-var-file-paths": true,

	// Targets that skip target validation: inline lists, internet search
	// engines (uncover), every IP of a host name, resumed scan files.
	"-targets-inline": true, "-uc": true, "-uncover": true,
	"-uq": true, "-uncover-query": true, "-ue": true, "-uncover-engine": true,
	"-sa": true, "-scan-all-ips": true, "-resume": true,

	// Short proxy spelling, proxying the tool's own requests.
	"-p": true, "-pi": true, "-proxy-internal": true,

	// Client TLS material read from the sensor's disk and presented to the
	// target (would hand the sensor's own key to an attacker's host).
	"-cc": true, "-client-cert": true, "-ck": true, "-client-key": true,
	"-ca": true, "-client-ca": true,

	// Results uploaded to a third-party cloud, listeners opened on the
	// sensor, the engine or template set replaced, state wiped, more files
	// written.
	"-auth": true, "-tid": true, "-team-id": true, "-cup": true, "-cloud-upload": true,
	"-pd": true, "-dashboard": true, "-pdu": true, "-dashboard-upload": true,
	"-sid": true, "-scan-id": true,
	"-dts": true, "-dast-server": true, "-dtsa": true, "-dast-server-address": true,
	"-dtst": true, "-dast-server-token": true, "-dtr": true, "-dast-report": true,
	"-hae": true, "-http-api-endpoint": true, "-ep": true, "-enable-pprof": true,
	"-up": true, "-update": true, "-ut": true, "-update-templates": true,
	"-ud": true, "-update-template-dir": true, "-reset": true,
	"-pe": true, "-pdf-export": true, "-project-path": true, "-profile-mem": true,
}

// RateLimitToolFlags are scanner CLI flags that set how hard a tool hits its
// targets (requests per second, hosts or templates in parallel). They never
// arrive through extra args: a scan asks for lower limits with the typed
// ScanOptions.RateLimit / BulkSize / Concurrency, and the sensor caps those
// at the ceilings its operator configured. A free-form "-rate-limit 100000"
// (or "-per-host-rate-limit", which lifts nuclei's global limit) would get
// around the ceiling.
var RateLimitToolFlags = map[string]bool{
	// nuclei (v3.11 -h, RATE-LIMIT), httpx, katana, dnsx, subfinder.
	"-rl": true, "-rate-limit": true, "-rld": true, "-rate-limit-duration": true,
	"-per-host-rate-limit": true, "-rlm": true, "-rate-limit-minute": true,
	"-bs": true, "-bulk-size": true, "-concurrency": true,
	"-hbs": true, "-headless-bulk-size": true, "-headc": true, "-headless-concurrency": true,
	"-jsc": true, "-js-concurrency": true, "-payload-concurrency": true,
	"-prc": true, "-probe-concurrency": true,
	// naabu, subfinder, dnsx, httpx.
	"-rate": true, "-rls": true, "-threads": true, "-parallelism": true,
}

// ValidateExtraArgs rejects extra CLI args that contain a DangerousToolFlags
// or RateLimitToolFlags entry, either bare ("-proxy") or in "flag=value"
// form ("-proxy=http://x"). Matching is case-insensitive, ignores
// surrounding whitespace and ignores how many dashes the flag has: Go's flag
// package (nuclei, httpx, katana, subfinder, dnsx, naabu) accepts "-proxy"
// and "--proxy" alike, so an entry listed as "-proxy" also blocks "--proxy"
// and "---proxy", and "--config" also blocks "-config".
func ValidateExtraArgs(args []string) error {
	for _, arg := range args {
		name, ok := flagName(arg)
		if !ok {
			continue
		}
		if inFlagSet(DangerousToolFlags, name) {
			return fmt.Errorf("extra arg %q is not allowed", arg)
		}
		if inFlagSet(RateLimitToolFlags, name) {
			return fmt.Errorf("extra arg %q is not allowed: rate limits come from the scan's typed options, capped by the sensor", arg)
		}
	}
	return nil
}

// flagName returns arg's flag name without dashes or "=value", lower-cased;
// false when arg is not a flag.
func flagName(arg string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(arg))
	if !strings.HasPrefix(lower, "-") {
		return "", false
	}
	name := strings.TrimLeft(lower, "-")
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return name, name != ""
}

func inFlagSet(set map[string]bool, name string) bool {
	return set["-"+name] || set["--"+name]
}
