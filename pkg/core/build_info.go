package core

import (
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// SDKInfo names the SDK a sensor is built with: heartbeat "sdk".
type SDKInfo struct {
	// Name is "openctem-sdk-go".
	Name string `json:"name"`
	// Version is the SDK version linked into the binary, without a leading
	// "v" (useragent.SDKVersion: from the build info, so a release tag sets
	// it; "<sdk.Version>-devel" for a local checkout).
	Version string `json:"version"`
}

// SensorBuild names the sensor binary: heartbeat "sensor".
type SensorBuild struct {
	// Name is the product name (BaseSensorConfig.ProductName, else the
	// name given to useragent.SetProduct, else the executable's name).
	Name string `json:"name"`
	// Version is the sensor's version, without a leading "v"; "" when the
	// sensor does not say.
	Version string `json:"version,omitempty"`
	// Commit is the source revision the binary was built from (optional).
	Commit string `json:"commit,omitempty"`
	// BuildTime is when the binary was built, RFC 3339 in UTC (optional).
	BuildTime string `json:"build_time,omitempty"`
}

// Bounds on the build fields a heartbeat carries.
const (
	maxBuildNameLen   = 128
	maxBuildCommitLen = 64
)

// CurrentSDKInfo is the SDK this binary is built with.
func CurrentSDKInfo() SDKInfo {
	return SDKInfo{Name: sdk.Name, Version: useragent.SDKVersion()}
}

// NewSensorBuild describes the sensor binary. Empty productName and version
// fall back to what was given to useragent.SetProduct, then (name only) to
// the executable's name. buildTime is kept only when it parses as RFC 3339
// (it is normalized to UTC); commit and the names are trimmed and bounded.
func NewSensorBuild(productName, version, commit, buildTime string) SensorBuild {
	uaName, uaVersion := useragent.ProductName()
	name := firstNonBlank(productName, uaName, executableName())
	b := SensorBuild{
		Name:    bound(name, maxBuildNameLen),
		Version: bound(strings.TrimPrefix(firstNonBlank(version, uaVersion), "v"), maxBuildNameLen),
		Commit:  bound(commit, maxBuildCommitLen),
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(buildTime)); err == nil {
		b.BuildTime = t.UTC().Format(time.RFC3339)
	}
	return b
}

func executableName() string {
	if len(os.Args) == 0 || os.Args[0] == "" {
		return ""
	}
	return filepath.Base(os.Args[0])
}

func firstNonBlank(vals ...string) string {
	for _, v := range vals {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func bound(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		s = s[:n]
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}
