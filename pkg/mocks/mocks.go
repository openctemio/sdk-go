// Package mocks provides mock implementations for testing.
// This follows AWS SDK, Google Cloud SDK patterns for testability.
package mocks

import (
	"context"
	"net/http"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// =============================================================================
// Mock Pusher
// =============================================================================

// MockPusher is a mock implementation of core.Pusher for testing.
type MockPusher struct {
	// PushFindingsFn is called when PushFindings is invoked
	PushFindingsFn func(ctx context.Context, report *ctis.Report) (*core.PushResult, error)

	// PushAssetsFn is called when PushAssets is invoked
	PushAssetsFn func(ctx context.Context, report *ctis.Report) (*core.PushResult, error)

	// SendHeartbeatFn is called when SendHeartbeat is invoked
	SendHeartbeatFn func(ctx context.Context, status *core.AgentStatus) error

	// TestConnectionFn is called when TestConnection is invoked
	TestConnectionFn func(ctx context.Context) error

	// Call tracking
	PushFindingsCalls   []PushFindingsCall
	PushAssetsCalls     []PushAssetsCall
	SendHeartbeatCalls  []SendHeartbeatCall
	TestConnectionCalls int
}

type PushFindingsCall struct {
	Report *ctis.Report
}

type PushAssetsCall struct {
	Report *ctis.Report
}

type SendHeartbeatCall struct {
	Status *core.AgentStatus
}

func (m *MockPusher) PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	m.PushFindingsCalls = append(m.PushFindingsCalls, PushFindingsCall{Report: report})
	if m.PushFindingsFn != nil {
		return m.PushFindingsFn(ctx, report)
	}
	return &core.PushResult{Success: true}, nil
}

func (m *MockPusher) PushAssets(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	m.PushAssetsCalls = append(m.PushAssetsCalls, PushAssetsCall{Report: report})
	if m.PushAssetsFn != nil {
		return m.PushAssetsFn(ctx, report)
	}
	return &core.PushResult{Success: true}, nil
}

func (m *MockPusher) SendHeartbeat(ctx context.Context, status *core.AgentStatus) error {
	m.SendHeartbeatCalls = append(m.SendHeartbeatCalls, SendHeartbeatCall{Status: status})
	if m.SendHeartbeatFn != nil {
		return m.SendHeartbeatFn(ctx, status)
	}
	return nil
}

func (m *MockPusher) TestConnection(ctx context.Context) error {
	m.TestConnectionCalls++
	if m.TestConnectionFn != nil {
		return m.TestConnectionFn(ctx)
	}
	return nil
}

// Ensure MockPusher implements core.Pusher
var _ core.Pusher = (*MockPusher)(nil)

// =============================================================================
// Mock Connector
// =============================================================================

// MockConnector is a mock implementation of core.Connector for testing.
type MockConnector struct {
	NameVal      string
	TypeVal      string
	ConnectedVal bool

	ConnectFn        func(ctx context.Context) error
	TestConnectionFn func(ctx context.Context) error
	CloseFn          func() error

	ConnectCalls        int
	TestConnectionCalls int
}

func (m *MockConnector) Name() string      { return m.NameVal }
func (m *MockConnector) Type() string      { return m.TypeVal }
func (m *MockConnector) IsConnected() bool { return m.ConnectedVal }
func (m *MockConnector) RateLimited() bool { return false }

func (m *MockConnector) Connect(ctx context.Context) error {
	m.ConnectCalls++
	if m.ConnectFn != nil {
		return m.ConnectFn(ctx)
	}
	m.ConnectedVal = true
	return nil
}

func (m *MockConnector) Close() error {
	if m.CloseFn != nil {
		return m.CloseFn()
	}
	m.ConnectedVal = false
	return nil
}

func (m *MockConnector) TestConnection(ctx context.Context) error {
	m.TestConnectionCalls++
	if m.TestConnectionFn != nil {
		return m.TestConnectionFn(ctx)
	}
	return nil
}

func (m *MockConnector) HTTPClient() *http.Client {
	return http.DefaultClient
}

func (m *MockConnector) WaitForRateLimit(ctx context.Context) error {
	return nil
}

// Ensure MockConnector implements core.Connector
var _ core.Connector = (*MockConnector)(nil)

// =============================================================================
// Mock Collector
// =============================================================================

// MockCollector is a mock implementation of core.Collector for testing.
type MockCollector struct {
	NameVal string
	TypeVal string

	CollectFn        func(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error)
	TestConnectionFn func(ctx context.Context) error

	CollectCalls int
}

func (m *MockCollector) Name() string { return m.NameVal }
func (m *MockCollector) Type() string { return m.TypeVal }

func (m *MockCollector) Collect(ctx context.Context, opts *core.CollectOptions) (*core.CollectResult, error) {
	m.CollectCalls++
	if m.CollectFn != nil {
		return m.CollectFn(ctx, opts)
	}
	return &core.CollectResult{
		SourceName: m.NameVal,
		Reports:    []*ctis.Report{ctis.NewReport()},
	}, nil
}

func (m *MockCollector) TestConnection(ctx context.Context) error {
	if m.TestConnectionFn != nil {
		return m.TestConnectionFn(ctx)
	}
	return nil
}

// Ensure MockCollector implements core.Collector
var _ core.Collector = (*MockCollector)(nil)

// =============================================================================
// Mock Scanner
// =============================================================================

// MockScanner is a mock implementation of core.Scanner for testing.
type MockScanner struct {
	NameVal         string
	VersionVal      string
	CapabilitiesVal []string
	InstalledVal    bool

	ScanFn        func(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error)
	IsInstalledFn func(ctx context.Context) (bool, string, error)

	ScanCalls        int
	IsInstalledCalls int
}

func (m *MockScanner) Name() string    { return m.NameVal }
func (m *MockScanner) Version() string { return m.VersionVal }

func (m *MockScanner) Capabilities() []string {
	if m.CapabilitiesVal != nil {
		return m.CapabilitiesVal
	}
	return []string{"sast"}
}

func (m *MockScanner) Scan(ctx context.Context, target string, opts *core.ScanOptions) (*core.ScanResult, error) {
	m.ScanCalls++
	if m.ScanFn != nil {
		return m.ScanFn(ctx, target, opts)
	}
	return &core.ScanResult{
		RawOutput: []byte("{}"),
		ExitCode:  0,
	}, nil
}

func (m *MockScanner) IsInstalled(ctx context.Context) (bool, string, error) {
	m.IsInstalledCalls++
	if m.IsInstalledFn != nil {
		return m.IsInstalledFn(ctx)
	}
	return m.InstalledVal, m.VersionVal, nil
}

// Ensure MockScanner implements core.Scanner
var _ core.Scanner = (*MockScanner)(nil)

// =============================================================================
// Mock Adapter
// =============================================================================

// MockAdapter is a mock implementation of core.Adapter for testing.
type MockAdapter struct {
	NameVal         string
	InputFormatsVal []string
	OutputFormatVal string
	CanConvertVal   bool

	ConvertFn func(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error)

	ConvertCalls int
}

func (m *MockAdapter) Name() string                 { return m.NameVal }
func (m *MockAdapter) InputFormats() []string       { return m.InputFormatsVal }
func (m *MockAdapter) OutputFormat() string         { return m.OutputFormatVal }
func (m *MockAdapter) CanConvert(input []byte) bool { return m.CanConvertVal }

func (m *MockAdapter) Convert(ctx context.Context, input []byte, opts *core.AdapterOptions) (*ctis.Report, error) {
	m.ConvertCalls++
	if m.ConvertFn != nil {
		return m.ConvertFn(ctx, input, opts)
	}
	return ctis.NewReport(), nil
}

// Ensure MockAdapter implements core.Adapter
var _ core.Adapter = (*MockAdapter)(nil)
