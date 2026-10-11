package core

import (
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

// SENSOR_ALLOW_PRIVATE_TARGETS is the one switch for private scan targets.
// The removed names (refused by the sensor kit at start-up) and the SDK's own
// egress switch never widen what may be scanned.
func TestDefaultScanTargetPolicyOneSwitch(t *testing.T) {
	resetEnv := func(t *testing.T) {
		t.Helper()
		for _, k := range []string{EnvSensorAllowPrivateTargets, "OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS", "AGENT_ALLOW_PRIVATE_TARGETS",
			"OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"} {
			unsetEnv(t, k)
		}
	}

	t.Run("the switch", func(t *testing.T) {
		resetEnv(t)
		t.Setenv(EnvSensorAllowPrivateTargets, "1")
		if p := DefaultScanTargetPolicy(); !p.AllowPrivate {
			t.Fatal("SENSOR_ALLOW_PRIVATE_TARGETS=1 must allow private targets")
		}
	})

	for _, other := range []string{"OPENCTEM_SDK_ALLOW_PRIVATE_TARGETS", "AGENT_ALLOW_PRIVATE_TARGETS", "OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"} {
		t.Run(other+" does not widen targets", func(t *testing.T) {
			resetEnv(t)
			t.Setenv(other, "1")
			if p := DefaultScanTargetPolicy(); p.AllowPrivate {
				t.Fatalf("%s=1 must not allow private scan targets", other)
			}
		})
	}

	t.Run("an unrecognized value is reported", func(t *testing.T) {
		resetEnv(t)
		t.Setenv(EnvSensorAllowPrivateTargets, "true")
		if err := CheckEnv(); err == nil || !strings.Contains(err.Error(), EnvSensorAllowPrivateTargets) {
			t.Fatalf("CheckEnv = %v, want an error naming the switch", err)
		}
	})
}
