package core

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

func TestScannerEnviron_Allowlist(t *testing.T) {
	base := []string{
		"PATH=/usr/bin",
		"HOME=/home/agent",
		"HTTPS_PROXY=http://proxy:3128",
		"LC_ALL=C.UTF-8",
		"XDG_CACHE_HOME=/cache",
		"TRIVY_CACHE_DIR=/cache/trivy",
		"NUCLEI_TEMPLATES_DIR=/nt",
		"SSL_CERT_FILE=/etc/ssl/ca.pem",
		// Must not leak:
		"OPENCTEM_API_KEY=oct_secret",
		"API_KEY=secret2",
		"AGENT_API_KEY=secret3",
		"AWS_SECRET_ACCESS_KEY=secret4",
		"BOOTSTRAP_TOKEN=secret5",
	}
	got := envMap(scannerEnviron(base, map[string]string{"SCANNER_FLAG": "1"}))

	for _, keep := range []string{"PATH", "HOME", "HTTPS_PROXY", "LC_ALL", "XDG_CACHE_HOME", "TRIVY_CACHE_DIR", "NUCLEI_TEMPLATES_DIR", "SSL_CERT_FILE", "SCANNER_FLAG"} {
		if _, ok := got[keep]; !ok {
			t.Errorf("%s dropped from scanner env", keep)
		}
	}
	for _, drop := range []string{"OPENCTEM_API_KEY", "API_KEY", "AGENT_API_KEY", "AWS_SECRET_ACCESS_KEY", "BOOTSTRAP_TOKEN"} {
		if _, ok := got[drop]; ok {
			t.Errorf("%s leaked into scanner env", drop)
		}
	}
}

func TestScannerEnviron_Configurable(t *testing.T) {
	t.Cleanup(func() {
		SetScannerEnvAllowlist(nil)
		SetScannerInheritEnv(false)
	})
	base := []string{"AWS_REGION=eu-west-1", "AWS_PROFILE=x", "GITHUB_TOKEN=t", "OTHER=o"}

	SetScannerEnvAllowlist([]string{"AWS_*", "GITHUB_TOKEN"})
	got := envMap(scannerEnviron(base))
	if got["AWS_REGION"] == "" || got["AWS_PROFILE"] == "" || got["GITHUB_TOKEN"] == "" {
		t.Errorf("extra allowlist not honored: %v", got)
	}
	if _, ok := got["OTHER"]; ok {
		t.Errorf("non-allowlisted var passed: %v", got)
	}

	SetScannerInheritEnv(true)
	if got := envMap(scannerEnviron(base)); got["OTHER"] != "o" {
		t.Errorf("inherit mode should pass everything: %v", got)
	}
}

// End to end: a real child process started by ExecuteScanner must not see
// the sensor's API key.
func TestExecuteScanner_DoesNotLeakCredentials(t *testing.T) {
	if _, err := exec.LookPath("env"); err != nil {
		t.Skip("env binary not available")
	}
	t.Setenv("OPENCTEM_API_KEY", "oct_must_not_leak")
	t.Setenv("API_KEY", "must_not_leak_either")

	res, err := ExecuteScanner(context.Background(), &ExecConfig{
		Binary: "env",
		Env:    map[string]string{"SCANNER_SETTING": "on"},
	})
	if err != nil {
		t.Fatal(err)
	}
	out := string(res.Stdout)
	if strings.Contains(out, "must_not_leak") {
		t.Fatalf("credential leaked to scanner process:\n%s", out)
	}
	if !strings.Contains(out, "SCANNER_SETTING=on") || !strings.Contains(out, "PATH=") {
		t.Fatalf("expected PATH and explicit env in child env:\n%s", out)
	}

	bs := NewBaseScanner(&BaseScannerConfig{Name: "env", Binary: "env", Env: map[string]string{"X_FROM_CONFIG": "1"}})
	r, err := bs.Scan(context.Background(), t.TempDir(), &ScanOptions{Env: map[string]string{"X_FROM_OPTS": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	out = string(r.RawOutput)
	if strings.Contains(out, "must_not_leak") {
		t.Fatalf("credential leaked via BaseScanner:\n%s", out)
	}
	if !strings.Contains(out, "X_FROM_CONFIG=1") || !strings.Contains(out, "X_FROM_OPTS=1") {
		t.Fatalf("BaseScanner dropped explicit env:\n%s", out)
	}
}

func TestMaskSecretInText(t *testing.T) {
	secret := "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
	cases := []struct {
		name, text, secret string
	}{
		{"embedded", `token = "` + secret + `"`, secret},
		{"repeated", secret + " " + secret, secret},
		{"secret missing from text", `token = "` + secret + `"`, "not-present-value"},
		{"empty secret", `password=` + secret, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := MaskSecretInText(tc.text, tc.secret)
			if strings.Contains(got, secret) {
				t.Fatalf("raw secret survived masking: %q", got)
			}
		})
	}
	if got := MaskSecretInText(`key="`+secret+`"`, secret); !strings.HasPrefix(got, `key="ghp_****`) {
		t.Errorf("context around the secret should be kept: %q", got)
	}
	if MaskSecretInText("", "x") != "" {
		t.Error("empty text should stay empty")
	}
}
