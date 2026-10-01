package core

import (
	"context"
	"os"
	"strings"
	"testing"
)

// unsetEnv removes k for the duration of the test (t.Setenv restores it).
func unsetEnv(t *testing.T, k string) {
	t.Helper()
	t.Setenv(k, "")
	if err := os.Unsetenv(k); err != nil {
		t.Fatal(err)
	}
}

// The private-targets switch was renamed AGENT_ALLOW_PRIVATE_TARGETS ->
// SENSOR_ALLOW_PRIVATE_TARGETS (RFC-023 §9.5). Both names must give the same
// posture, and a contradiction must fail closed.
func TestDefaultScanTargetPolicyRenamedEnv(t *testing.T) {
	resetEnv := func(t *testing.T) {
		t.Helper()
		for _, k := range []string{EnvAllowPrivateTargets, EnvSensorAllowPrivateTargets, "AGENT_ALLOW_PRIVATE_TARGETS",
			"OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"} {
			unsetEnv(t, k)
		}
	}

	t.Run("new name", func(t *testing.T) {
		resetEnv(t)
		t.Setenv(EnvSensorAllowPrivateTargets, "1")
		if p := DefaultScanTargetPolicy(); !p.AllowPrivate {
			t.Fatal("SENSOR_ALLOW_PRIVATE_TARGETS=1 must allow private targets")
		}
	})

	t.Run("old name is still honored", func(t *testing.T) {
		resetEnv(t)
		t.Setenv("AGENT_ALLOW_PRIVATE_TARGETS", "1")
		p := DefaultScanTargetPolicy()
		if !p.AllowPrivate {
			t.Fatal("AGENT_ALLOW_PRIVATE_TARGETS=1 must still allow private targets")
		}
		if err := CheckEnv(); err != nil {
			t.Fatalf("CheckEnv: %v", err)
		}
	})

	t.Run("conflict refuses every target", func(t *testing.T) {
		resetEnv(t)
		t.Setenv(EnvSensorAllowPrivateTargets, "1")
		t.Setenv("AGENT_ALLOW_PRIVATE_TARGETS", "0")
		p := DefaultScanTargetPolicy()
		if p.AllowPrivate {
			t.Fatal("a conflict must not allow private targets")
		}
		_, err := p.Validate(context.Background(), "example.com")
		if err == nil || !strings.Contains(err.Error(), "AGENT_ALLOW_PRIVATE_TARGETS") || !strings.Contains(err.Error(), "SENSOR_ALLOW_PRIVATE_TARGETS") {
			t.Fatalf("Validate = %v, want a refusal naming both variables", err)
		}
		if err := CheckEnv(); err == nil {
			t.Fatal("CheckEnv must report the conflict")
		}
	})
}
