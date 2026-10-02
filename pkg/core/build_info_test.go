package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

func TestCurrentSDKInfo(t *testing.T) {
	i := CurrentSDKInfo()
	if i.Name != "openctem-sdk-go" || i.Version != useragent.SDKVersion() {
		t.Fatalf("%+v", i)
	}
	// In `go test` the SDK is the main module, built from a checkout.
	if i.Version != sdk.Version+"-devel" {
		t.Fatalf("version %q, want %q in a test build", i.Version, sdk.Version+"-devel")
	}
}

func TestNewSensorBuild(t *testing.T) {
	b := NewSensorBuild("openctemio-sensor", "v1.2.3", " abc123 ", "2026-10-02T09:30:00+07:00")
	want := SensorBuild{Name: "openctemio-sensor", Version: "1.2.3", Commit: "abc123", BuildTime: "2026-10-02T02:30:00Z"}
	if b != want {
		t.Fatalf("got %+v want %+v", b, want)
	}
	// Defaults: the executable's name; no version; a bad build time is dropped.
	b = NewSensorBuild("", "", "", "yesterday")
	if b.Name != filepath.Base(os.Args[0]) || b.Version != "" || b.BuildTime != "" {
		t.Fatalf("defaults %+v", b)
	}
	// Bounds and control characters.
	b = NewSensorBuild(strings.Repeat("n", 300), "1.0\n", strings.Repeat("c", 100), "")
	if len(b.Name) != maxBuildNameLen || len(b.Commit) != maxBuildCommitLen || b.Version != "1.0" {
		t.Fatalf("bounds %+v", b)
	}
	// JSON names.
	data, _ := json.Marshal(SensorBuild{Name: "s", Version: "1", Commit: "c", BuildTime: "2026-10-02T00:00:00Z"})
	if string(data) != `{"name":"s","version":"1","commit":"c","build_time":"2026-10-02T00:00:00Z"}` {
		t.Fatalf("json %s", data)
	}
	data, _ = json.Marshal(SensorBuild{Name: "s"})
	if string(data) != `{"name":"s"}` {
		t.Fatalf("json omitempty %s", data)
	}
}

// The product given to useragent.SetProduct names the sensor when the
// config does not (a sensor that already calls SetProduct needs no change).
func TestNewSensorBuild_FromUserAgentProduct(t *testing.T) {
	useragent.SetProduct("openctemio-sensor", "v0.5.0")
	t.Cleanup(func() { useragent.SetProduct("", "") })
	if b := NewSensorBuild("", "", "", ""); b.Name != "openctemio-sensor" || b.Version != "0.5.0" {
		t.Fatalf("%+v", b)
	}
	if b := NewSensorBuild("custom", "2.0", "", ""); b.Name != "custom" || b.Version != "2.0" {
		t.Fatalf("config wins: %+v", b)
	}
}
