// Package adapters provides a registry for scanner output adapters.
// Each adapter converts a specific scanner's output format to CTIS.
//
// Deprecated: the converters duplicate ctis.FromSARIF and the parsers the
// sensor ships; no sensor, platform or collector imports them. Emit CTIS
// from a tool (pkg/tool) or convert SARIF with the ctis module. Removal is
// planned for a later minor release (docs/STABILITY.md).
package adapters

import (
	"context"
	"fmt"
	"sync"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"

	"github.com/openctemio/sdk-go/pkg/adapters/betterleaks" //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/nuclei"      //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/semgrep"     //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/trivy"       //nolint:staticcheck // deprecated together with this package
	"github.com/openctemio/sdk-go/pkg/adapters/vuls"        //nolint:staticcheck // deprecated together with this package
)

// Registry manages registered scanner adapters.
type Registry struct {
	adapters map[string]core.Adapter
	mu       sync.RWMutex
}

// NewRegistry creates a new adapter registry with built-in adapters.
func NewRegistry() *Registry {
	r := &Registry{
		adapters: make(map[string]core.Adapter),
	}

	// Register built-in adapters
	r.Register(trivy.NewAdapter())
	r.Register(nuclei.NewAdapter())
	r.Register(semgrep.NewAdapter())
	r.Register(betterleaks.NewAdapter())
	r.Register(vuls.NewAdapter())

	return r
}

// Register adds an adapter to the registry.
func (r *Registry) Register(adapter core.Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.adapters[adapter.Name()] = adapter
}

// Get returns an adapter by name.
func (r *Registry) Get(name string) (core.Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[name]
	return a, ok
}

// List returns all registered adapter names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.adapters))
	for name := range r.adapters {
		names = append(names, name)
	}
	return names
}

// AutoDetect tries to find an adapter that can convert the input.
func (r *Registry) AutoDetect(input []byte) (core.Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, adapter := range r.adapters {
		if adapter.CanConvert(input) {
			return adapter, true
		}
	}
	return nil, false
}

// Convert uses the specified adapter (or auto-detects) to convert input to CTIS.
func (r *Registry) Convert(ctx context.Context, scannerType string, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	var adapter core.Adapter

	if scannerType != "" {
		var ok bool
		adapter, ok = r.Get(scannerType)
		if !ok {
			return nil, fmt.Errorf("unknown scanner type: %s, supported: %v", scannerType, r.List())
		}
	} else {
		var ok bool
		adapter, ok = r.AutoDetect(input)
		if !ok {
			return nil, fmt.Errorf("could not auto-detect scanner format, please specify scanner_type")
		}
	}

	return adapter.Convert(ctx, input, opts)
}
