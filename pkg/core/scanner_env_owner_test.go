package core

import "testing"

var ownedBase = []string{
	"PATH=/usr/bin",
	"HOME=/h",
	"HTTPS_PROXY=http://proxy:3128",
	"TRIVY_PASSWORD=trivy-secret",
	"SEMGREP_APP_TOKEN=semgrep-secret",
	"PDCP_API_KEY=pd-secret",
	"NUCLEI_TEMPLATES_DIR=/nt",
	"GITLEAKS_CONFIG=/gl.toml",
	"DOCKER_HOST=tcp://docker:2376",
	"DOCKER_CONFIG=/docker-creds",
}

// A vendor namespace goes only to the tool it belongs to: one tool cannot
// read another tool's credentials.
func TestScannerEnvironFor_OwnNamespaceOnly(t *testing.T) {
	t.Cleanup(func() { SetScannerEnvAllowlist(nil); SetScannerInheritEnv(false) })
	env := scannerEnviron(ownedBase)
	cases := map[string]struct{ keep, drop []string }{
		"semgrep":     {keep: []string{"SEMGREP_APP_TOKEN"}, drop: []string{"TRIVY_PASSWORD", "PDCP_API_KEY", "NUCLEI_TEMPLATES_DIR", "DOCKER_HOST", "DOCKER_CONFIG", "GITLEAKS_CONFIG"}},
		"trivy":       {keep: []string{"TRIVY_PASSWORD", "DOCKER_HOST", "DOCKER_CONFIG"}, drop: []string{"SEMGREP_APP_TOKEN", "PDCP_API_KEY"}},
		"nuclei":      {keep: []string{"NUCLEI_TEMPLATES_DIR", "PDCP_API_KEY"}, drop: []string{"TRIVY_PASSWORD", "SEMGREP_APP_TOKEN", "DOCKER_HOST"}},
		"httpx":       {keep: []string{"PDCP_API_KEY"}, drop: []string{"NUCLEI_TEMPLATES_DIR", "TRIVY_PASSWORD"}},
		"betterleaks": {keep: []string{"GITLEAKS_CONFIG"}, drop: []string{"SEMGREP_APP_TOKEN"}},
		// An operator-installed program: no vendor namespace at all.
		"": {drop: []string{"TRIVY_PASSWORD", "SEMGREP_APP_TOKEN", "PDCP_API_KEY", "NUCLEI_TEMPLATES_DIR", "DOCKER_HOST", "DOCKER_CONFIG", "GITLEAKS_CONFIG"}},
	}
	for tool, c := range cases {
		got := envMap(scannerEnvironFor(tool, env))
		for _, k := range c.keep {
			if _, ok := got[k]; !ok {
				t.Errorf("tool %q: its own %s was dropped", tool, k)
			}
		}
		for _, k := range c.drop {
			if _, ok := got[k]; ok {
				t.Errorf("tool %q received %s, another tool's variable", tool, k)
			}
		}
		for _, k := range []string{"PATH", "HOME", "HTTPS_PROXY"} {
			if _, ok := got[k]; !ok {
				t.Errorf("tool %q: shared variable %s dropped", tool, k)
			}
		}
	}
}

// What the caller passes explicitly, and what the operator allows by
// name, still reaches any tool.
func TestScannerEnvironFor_ExplicitWins(t *testing.T) {
	t.Cleanup(func() { SetScannerEnvAllowlist(nil); SetScannerInheritEnv(false) })
	extra := map[string]string{"TRIVY_SERVER": "http://trivy:4954"}
	got := envMap(scannerEnvironFor("", scannerEnviron(ownedBase, extra), extra))
	if got["TRIVY_SERVER"] != "http://trivy:4954" {
		t.Errorf("explicit variable dropped: %v", got)
	}

	SetScannerEnvAllowlist([]string{"PDCP_*"})
	got = envMap(scannerEnvironFor("semgrep", scannerEnviron(ownedBase)))
	if got["PDCP_API_KEY"] == "" {
		t.Error("an operator-allowed prefix was dropped")
	}
	if _, ok := got["TRIVY_PASSWORD"]; ok {
		t.Error("the allowlist widened to a namespace it does not name")
	}

	SetScannerEnvAllowlist(nil)
	SetScannerInheritEnv(true)
	got = envMap(scannerEnvironFor("", ownedBase))
	if got["TRIVY_PASSWORD"] == "" {
		t.Error("inherit mode passes the whole environment")
	}
}
