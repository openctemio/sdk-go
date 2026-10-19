package sensorkit

import (
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
)

func TestResolveRequireSignedJobs_PinnedCannotBeTurnedOffByEnv(t *testing.T) {
	t.Setenv(core.EnvRequireSignedJobs, "false")
	t.Setenv(core.EnvDangerousAllowUnsignedJobs, "")
	_, _, err := ResolveRequireSignedJobs(1)
	if err == nil {
		t.Fatal("env=false on a sensor with pinned keys was accepted")
	}
	for _, want := range []string{core.EnvRequireSignedJobs, core.EnvDangerousAllowUnsignedJobs, "pinned"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
	if ExitCode(err) != ExitUsage {
		t.Fatalf("error %v is not a usage error", err)
	}
}

func TestResolveRequireSignedJobs_DangerousFlagAllowsWithMarker(t *testing.T) {
	t.Setenv(core.EnvRequireSignedJobs, "false")
	t.Setenv(core.EnvDangerousAllowUnsignedJobs, "1")
	req, from, err := ResolveRequireSignedJobs(2)
	if err != nil || req || from != requireFromDangerous {
		t.Fatalf("got %v %q %v, want not required from the dangerous flag", req, from, err)
	}
}

func TestResolveRequireSignedJobs_EnvMayStillRaise(t *testing.T) {
	t.Setenv(core.EnvRequireSignedJobs, "true")
	if req, from, err := ResolveRequireSignedJobs(0); err != nil || !req || from != requireFromEnv {
		t.Fatalf("raise: %v %q %v", req, from, err)
	}
	// Unpinned: false stays allowed (posture off, warned at start).
	t.Setenv(core.EnvRequireSignedJobs, "false")
	if req, _, err := ResolveRequireSignedJobs(0); err != nil || req {
		t.Fatalf("unpinned false: %v %v", req, err)
	}
	t.Setenv(core.EnvRequireSignedJobs, "")
	if req, from, err := ResolveRequireSignedJobs(1); err != nil || !req || from != requireFromIdentity {
		t.Fatalf("pinned default: %v %q %v", req, from, err)
	}
}
