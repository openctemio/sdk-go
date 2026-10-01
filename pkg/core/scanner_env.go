package core

import (
	"os"
	"strings"
	"sync"
)

// Scanner child-process environment.
//
// Scanner binaries (nuclei, trivy, semgrep, gitleaks, custom tools) used to
// inherit the sensor's whole environment, which includes the OpenCTEM API key,
// bootstrap tokens and any cloud credentials the sensor runs with. A scanner,
// a malicious template it loads, or a compromised scanner binary could read
// and exfiltrate them. Scanners now receive an allowlisted environment: the
// variables they need to run (PATH, HOME, temp/locale, proxy and CA settings)
// plus their own tool-prefixed configuration (TRIVY_*, NUCLEI_*, SEMGREP_*,
// GITLEAKS_*, CODEQL_*, and the ProjectDiscovery recon tools' prefixes).
//
// Configuration, in increasing order of scope:
//   - ExecConfig.Env / BaseScannerConfig.Env / ScanOptions.Env: explicit
//     per-scanner variables, always passed.
//   - OPENCTEM_SDK_SCANNER_ENV_ALLOW: comma-separated extra names to pass
//     through; an entry ending in '*' is a prefix (e.g. "AWS_*,GITHUB_TOKEN").
//   - SetScannerEnvAllowlist: the same, programmatically.
//   - OPENCTEM_SDK_SCANNER_INHERIT_ENV=1 or SetScannerInheritEnv(true):
//     restore the old behavior (full inheritance). Not recommended.

// scannerEnvAllowExact are variables passed through by exact name.
var scannerEnvAllowExact = []string{
	// Process basics
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "TZ",
	"TMPDIR", "TMP", "TEMP",
	"LANG", "LANGUAGE",
	// Proxies (both spellings are honored by different tools)
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
	"http_proxy", "https_proxy", "no_proxy", "all_proxy",
	// Custom CA bundles (corporate TLS interception)
	"SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
	// Container runtime access (trivy image scans)
	"DOCKER_HOST", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY", "CONTAINER_HOST",
	// Go runtime tuning for Go-based scanners
	"GOMAXPROCS", "GOMEMLIMIT",
	// Windows essentials
	"SYSTEMROOT", "SystemRoot", "WINDIR", "COMSPEC", "PATHEXT",
	"APPDATA", "LOCALAPPDATA", "USERPROFILE", "PROGRAMDATA", "ProgramData",
}

// scannerEnvAllowPrefixes are variable-name prefixes passed through: locale
// and XDG dirs (scanner caches live under XDG_CACHE_HOME) and each bundled
// scanner's own configuration namespace.
var scannerEnvAllowPrefixes = []string{
	"LC_",
	"XDG_",
	"TRIVY_",
	"NUCLEI_",
	"SEMGREP_",
	"GITLEAKS_",
	"CODEQL_",
	// ProjectDiscovery recon tools (subfinder, httpx, dnsx, naabu, katana)
	// and their cloud integration.
	"SUBFINDER_",
	"HTTPX_",
	"DNSX_",
	"NAABU_",
	"KATANA_",
	"PDCP_",
}

var (
	scannerEnvMu     sync.RWMutex
	scannerEnvExtra  = parseEnvAllowList(os.Getenv("OPENCTEM_SDK_SCANNER_ENV_ALLOW"))
	scannerInheritEn = os.Getenv("OPENCTEM_SDK_SCANNER_INHERIT_ENV") == "1"
)

// SetScannerEnvAllowlist adds variable names to the scanner environment
// allowlist, replacing any previous call's list (the env var list is
// replaced too). A name ending in '*' is treated as a prefix.
func SetScannerEnvAllowlist(names []string) {
	scannerEnvMu.Lock()
	defer scannerEnvMu.Unlock()
	scannerEnvExtra = append([]string(nil), names...)
}

// SetScannerInheritEnv makes scanner processes inherit the full
// sensor environment when inherit is true (the pre-hardening behavior). Only for setups
// where a scanner needs variables that cannot be enumerated.
func SetScannerInheritEnv(inherit bool) {
	scannerEnvMu.Lock()
	defer scannerEnvMu.Unlock()
	scannerInheritEn = inherit
}

func parseEnvAllowList(v string) []string {
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ScannerEnviron returns the environment for a scanner child process: the
// allowlisted subset of the current environment followed by extra (which
// wins on conflict because later entries take precedence in exec).
func ScannerEnviron(extra ...map[string]string) []string {
	return scannerEnviron(os.Environ(), extra...)
}

func scannerEnviron(base []string, extra ...map[string]string) []string {
	scannerEnvMu.RLock()
	inherit := scannerInheritEn
	allowExtra := scannerEnvExtra
	scannerEnvMu.RUnlock()

	env := make([]string, 0, len(base))
	for _, kv := range base {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		if inherit || scannerEnvAllowed(name, allowExtra) {
			env = append(env, kv)
		}
	}
	for _, m := range extra {
		for k, v := range m {
			env = append(env, k+"="+v)
		}
	}
	return env
}

func scannerEnvAllowed(name string, extra []string) bool {
	for _, n := range scannerEnvAllowExact {
		if name == n {
			return true
		}
	}
	for _, p := range scannerEnvAllowPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, e := range extra {
		if prefix, ok := strings.CutSuffix(e, "*"); ok {
			if prefix != "" && strings.HasPrefix(name, prefix) {
				return true
			}
			continue
		}
		if name == e {
			return true
		}
	}
	return false
}
