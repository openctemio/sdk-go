package sensorkit

import (
	"fmt"
	"strings"

	"github.com/openctemio/sdk-go/pkg/tool"
)

// AdapterTool is an operator-installed tool the sensor loads.
type AdapterTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	// Manifest is the path of the tool.yaml.
	Manifest string `json:"manifest"`
	// Digest is the manifest digest the platform sees in the sensor's
	// tool report.
	Digest     string   `json:"digest"`
	Implements []string `json:"implements,omitempty"`
	Class      string   `json:"class"`
	Tier       string   `json:"tier"`
	Network    string   `json:"network"`
}

// AdapterRefusal is a manifest the sensor does not load, and why.
type AdapterRefusal struct {
	Manifest string `json:"manifest"`
	Reason   string `json:"reason"`
}

// AdapterReport is what the adapter directories yield.
type AdapterReport struct {
	Loaded  []AdapterTool    `json:"loaded"`
	Refused []AdapterRefusal `json:"refused"`

	loaded []adapterLoaded
}

type adapterLoaded struct {
	m    tool.Manifest
	path string
}

// InspectAdapterDirs reports which tools the sensor would load from the
// adapter directories (SENSOR_ADAPTER_DIRS) and why it refuses any other,
// without starting a sensor or contacting a platform. builtin are the names
// of the tools compiled into the sensor (a manifest with one of them is
// refused). The kit loads its adapter tools from the same call, so the two
// never disagree. Reading only: nothing is registered or executed.
func InspectAdapterDirs(dirs []string, builtin []string) AdapterReport {
	return inspectAdapterDirs(dirs, builtin)
}

func inspectAdapterDirs(dirs []string, builtin []string) AdapterReport {
	rep := AdapterReport{Loaded: []AdapterTool{}, Refused: []AdapterRefusal{}}
	taken := map[string]bool{}
	for _, n := range builtin {
		taken[strings.ToLower(n)] = true
	}
	refuse := func(path string, err error) {
		rep.Refused = append(rep.Refused, AdapterRefusal{Manifest: path, Reason: err.Error()})
	}
	for _, dir := range dirs {
		for _, mf := range adapterManifests(dir) {
			if len(rep.loaded) >= maxAdapterTools {
				refuse(mf, fmt.Errorf("more than %d adapter tools; the rest are not loaded", maxAdapterTools))
				return rep
			}
			m, err := loadAdapterManifest(dir, mf)
			if err != nil {
				refuse(mf, err)
				continue
			}
			if taken[m.Name] {
				refuse(mf, fmt.Errorf("tool %s is already provided by the sensor", m.Name))
				continue
			}
			taken[m.Name] = true
			rep.loaded = append(rep.loaded, adapterLoaded{m: m, path: mf})
			at := AdapterTool{Name: m.Name, Version: m.Version, Manifest: mf, Digest: m.Digest(),
				Class: string(m.Class), Tier: string(m.Tier), Network: string(m.Permissions.Network)}
			for _, im := range m.Implements {
				at.Implements = append(at.Implements, im.Capability)
			}
			rep.Loaded = append(rep.Loaded, at)
		}
	}
	return rep
}
