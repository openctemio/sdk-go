package core

import (
	"slices"
	"strings"
)

// Each bundled tool's configuration namespace is that tool's own: it holds
// the tool's credentials (TRIVY_PASSWORD, SEMGREP_APP_TOKEN, PDCP_API_KEY,
// a registry's DOCKER_CONFIG, ...). ScannerEnvironFor passes a namespace
// only to the tools it belongs to, so one tool (or a hostile template it
// loads) cannot read another's credentials, and a tool the operator
// installed from outside the project gets none: it receives the credentials
// its manifest declares through the run message.

// projectDiscoveryTools share the PDCP_ cloud namespace.
var projectDiscoveryTools = []string{"nuclei", "subfinder", "httpx", "dnsx", "naabu", "katana"}

// scannerEnvPrefixOwners are the tools each vendor prefix belongs to.
var scannerEnvPrefixOwners = map[string][]string{
	"TRIVY_":       {"trivy"},
	"NUCLEI_":      {"nuclei"},
	"SEMGREP_":     {"semgrep"},
	"BETTERLEAKS_": {"betterleaks"},
	"GITLEAKS_":    {"betterleaks"},
	"CODEQL_":      {"codeql"},
	"SUBFINDER_":   {"subfinder"},
	"HTTPX_":       {"httpx"},
	"DNSX_":        {"dnsx"},
	"NAABU_":       {"naabu"},
	"KATANA_":      {"katana"},
	"PDCP_":        projectDiscoveryTools,
}

// scannerEnvExactOwners are the tools each container runtime variable
// belongs to (trivy's image scans).
var scannerEnvExactOwners = map[string][]string{
	"DOCKER_HOST":       {"trivy"},
	"DOCKER_CONFIG":     {"trivy"},
	"DOCKER_CERT_PATH":  {"trivy"},
	"DOCKER_TLS_VERIFY": {"trivy"},
	"CONTAINER_HOST":    {"trivy"},
}

// ScannerEnvironFor is ScannerEnviron for one tool: a vendor namespace
// (TRIVY_*, SEMGREP_*, PDCP_*, the container runtime variables, ...) is
// passed only to the tool it belongs to. tool is the bundled tool's name;
// "" is a program the operator installed, which gets no vendor namespace.
// The variables in extra, and those the operator allows by name
// (OPENCTEM_SDK_SCANNER_ENV_ALLOW, SetScannerEnvAllowlist) or by inheriting
// the whole environment, are passed as ScannerEnviron passes them.
func ScannerEnvironFor(tool string, extra ...map[string]string) []string {
	return scannerEnvironFor(tool, ScannerEnviron(extra...), extra...)
}

func scannerEnvironFor(tool string, env []string, extra ...map[string]string) []string {
	scannerEnvMu.RLock()
	inherit := scannerInheritEn
	allowExtra := scannerEnvExtra
	scannerEnvMu.RUnlock()
	if inherit {
		return env
	}
	explicit := map[string]bool{}
	for _, m := range extra {
		for k := range m {
			explicit[k] = true
		}
	}
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if owners, owned := envOwners(name); owned && !slices.Contains(owners, tool) &&
			!explicit[name] && !operatorAllowed(name, allowExtra) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// envOwners are the tools a variable belongs to (owned false: any tool's).
func envOwners(name string) ([]string, bool) {
	if o, ok := scannerEnvExactOwners[name]; ok {
		return o, true
	}
	for p, o := range scannerEnvPrefixOwners {
		if strings.HasPrefix(name, p) {
			return o, true
		}
	}
	return nil, false
}

// operatorAllowed reports whether the operator's own allowlist names the
// variable (by name or prefix).
func operatorAllowed(name string, allow []string) bool {
	for _, e := range allow {
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
