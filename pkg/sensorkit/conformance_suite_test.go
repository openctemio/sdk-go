package sensorkit

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// A sensor built on the kit passes the conformance suite a third-party
// sensor runs: the suite and the kit must agree, or the suite is wrong.
func TestKitPassesSensorConformanceSuite(t *testing.T) {
	prev := httpsec.AllowLoopback
	httpsec.AllowLoopback = true
	t.Cleanup(func() { httpsec.AllowLoopback = prev })

	target := t.TempDir()
	conformance.RunSensorSuite(t, func(t *testing.T, p conformance.SensorEndpoint) func() {
		clearEnv(t)
		t.Setenv("HOME", t.TempDir())
		t.Setenv(EnvDrainGrace, "1s")
		persistentState(t, false)
		opts := Options{
			Name: "kit-conformance", Version: "1.2.3",
			APIURL: p.URL, APIKey: p.APIKey,
			Outbox:   OutboxSettings{Dir: filepath.Join(t.TempDir(), "outbox")},
			StateDir: t.TempDir(),
			Stdout:   &syncBuffer{}, Stderr: &syncBuffer{},
		}
		opts.ScanTargetPolicy = &core.ScanTargetPolicy{AllowedRoots: []string{target}}
		opts.AssetResolver = func(_, _ string) (ctis.AssetType, string) {
			return ctis.AssetTypeRepository, "github.com/openctemio/kit-conformance"
		}
		k, err := New(opts)
		if err != nil {
			t.Fatal(err)
		}
		k.AddScanner(&testScanner{name: "kit-tool", installed: true})
		stop := runKit(t, k)
		return func() {
			if err := stop(); err != nil {
				t.Errorf("Run: %v", err)
			}
		}
	}, conformance.SuiteOptions{
		ScanPayload: json.RawMessage(fmt.Sprintf(`{"scanner":"kit-tool","target":%q}`, target)),
		Timeout:     30 * time.Second,
	})
}
