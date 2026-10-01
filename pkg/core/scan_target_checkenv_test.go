package core

import (
	"os"
	"strings"
	"testing"
)

func TestCheckEnv_AllowPrivateValues(t *testing.T) {
	for _, tc := range []struct {
		name, env, value string
		wantErr          bool
	}{
		{"unset", EnvSensorAllowPrivateTargets, "", false},
		{"one", EnvSensorAllowPrivateTargets, "1", false},
		{"zero", EnvSensorAllowPrivateTargets, "0", false},
		{"true is not silently ignored", EnvSensorAllowPrivateTargets, "true", true},
		{"yes", EnvAllowPrivateTargets, "yes", true},
		{"httpsec switch", "OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", "on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, n := range []string{EnvAllowPrivateTargets, EnvSensorAllowPrivateTargets, "AGENT_ALLOW_PRIVATE_TARGETS",
				"OPENCTEM_SDK_HTTPSEC_ALLOW_PRIVATE", "OPENCTEM_HTTPSEC_ALLOW_PRIVATE"} {
				t.Setenv(n, "") // restores the original value after the test
				os.Unsetenv(n)
			}
			if tc.value != "" {
				t.Setenv(tc.env, tc.value)
			}
			err := CheckEnv()
			if (err != nil) != tc.wantErr {
				t.Fatalf("CheckEnv() = %v, wantErr %v", err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), tc.env) {
				t.Fatalf("error %q does not name %s", err, tc.env)
			}
		})
	}
}
