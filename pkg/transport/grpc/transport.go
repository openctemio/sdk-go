// Package grpc provides a gRPC transport layer for the OpenCTEM SDK client.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
)

// Transport provides gRPC connectivity for the SDK client.
type Transport struct {
	conn    *grpc.ClientConn
	config  *Config
	mu      sync.RWMutex
	verbose bool
}

// Config holds gRPC transport configuration.
type Config struct {
	// Server address (host:port)
	Address string `yaml:"address" json:"address"`

	// Authentication
	APIKey  string `yaml:"api_key" json:"api_key"`
	AgentID string `yaml:"agent_id" json:"agent_id"`

	// TLS configuration
	UseTLS             bool   `yaml:"use_tls" json:"use_tls"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify" json:"insecure_skip_verify"`
	CertFile           string `yaml:"cert_file" json:"cert_file"`

	// Connection settings
	Timeout          time.Duration `yaml:"timeout" json:"timeout"`
	KeepAliveTime    time.Duration `yaml:"keepalive_time" json:"keepalive_time"`
	KeepAliveTimeout time.Duration `yaml:"keepalive_timeout" json:"keepalive_timeout"`
	MaxRecvMsgSize   int           `yaml:"max_recv_msg_size" json:"max_recv_msg_size"`
	MaxSendMsgSize   int           `yaml:"max_send_msg_size" json:"max_send_msg_size"`

	// Debug
	Verbose bool `yaml:"verbose" json:"verbose"`
}

// DefaultConfig returns default gRPC config.
func DefaultConfig() *Config {
	return &Config{
		Address:          "localhost:9090",
		UseTLS:           true,
		Timeout:          30 * time.Second,
		KeepAliveTime:    30 * time.Second,
		KeepAliveTimeout: 10 * time.Second,
		MaxRecvMsgSize:   50 * 1024 * 1024, // 50MB
		MaxSendMsgSize:   50 * 1024 * 1024, // 50MB
	}
}

// NewTransport creates a new gRPC transport.
func NewTransport(cfg *Config) *Transport {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Transport{
		config:  cfg,
		verbose: cfg.Verbose,
	}
}

// Connect establishes the gRPC connection.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		return nil // Already connected
	}

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(t.config.MaxRecvMsgSize),
			grpc.MaxCallSendMsgSize(t.config.MaxSendMsgSize),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                t.config.KeepAliveTime,
			Timeout:             t.config.KeepAliveTimeout,
			PermitWithoutStream: true,
		}),
		grpc.WithUnaryInterceptor(t.authInterceptor()),
		grpc.WithStreamInterceptor(t.streamAuthInterceptor()),
	}

	// TLS configuration
	if t.config.UseTLS {
		// Extract hostname for ServerName from address
		serverName := extractHostname(t.config.Address)

		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: serverName, // Proper hostname verification
		}

		// SECURITY WARNING: InsecureSkipVerify disables certificate verification
		// This should ONLY be used for development/testing environments
		if t.config.InsecureSkipVerify {
			log.Printf("[SECURITY WARNING] TLS certificate verification is DISABLED for %s. "+
				"This is insecure and should NOT be used in production!", t.config.Address)
			tlsConfig.InsecureSkipVerify = true //nolint:gosec // Intentional for dev environments, logged warning above
		}

		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		// SECURITY WARNING: Insecure connection
		log.Printf("[SECURITY WARNING] Using insecure (non-TLS) connection to %s. "+
			"Enable TLS for production use!", t.config.Address)
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	if t.verbose {
		fmt.Printf("[grpc] Connecting to %s (TLS: %v)\n", t.config.Address, t.config.UseTLS)
	}

	//nolint:staticcheck // Using DialContext for backward compatibility until fully migrated to NewClient
	conn, err := grpc.DialContext(ctx, t.config.Address, opts...)
	if err != nil {
		return fmt.Errorf("grpc dial: %w", err)
	}

	t.conn = conn

	if t.verbose {
		fmt.Printf("[grpc] Connected to %s\n", t.config.Address)
	}

	return nil
}

// Close closes the gRPC connection.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return nil
	}

	err := t.conn.Close()
	t.conn = nil

	if t.verbose {
		fmt.Println("[grpc] Connection closed")
	}

	return err
}

// Conn returns the underlying gRPC connection.
func (t *Transport) Conn() *grpc.ClientConn {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn
}

// IsConnected returns true if connected.
func (t *Transport) IsConnected() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.conn != nil
}

// authInterceptor adds authentication metadata to unary calls.
func (t *Transport) authInterceptor() grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{},
		cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		ctx = t.addAuthMetadata(ctx)
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// streamAuthInterceptor adds authentication metadata to streaming calls.
func (t *Transport) streamAuthInterceptor() grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn,
		method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		ctx = t.addAuthMetadata(ctx)
		return streamer(ctx, desc, cc, method, opts...)
	}
}

// addAuthMetadata adds authentication headers to context.
func (t *Transport) addAuthMetadata(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"authorization": "Bearer " + t.config.APIKey,
	})
	if t.config.AgentID != "" {
		md.Set("x-agent-id", t.config.AgentID)
	}
	return metadata.NewOutgoingContext(ctx, md)
}

// extractHostname extracts the hostname from an address for TLS ServerName.
func extractHostname(address string) string {
	// Handle both "host:port" and "scheme://host:port" formats
	if strings.Contains(address, "://") {
		if u, err := url.Parse(address); err == nil {
			return u.Hostname()
		}
	}
	// Handle "host:port" format
	if idx := strings.LastIndex(address, ":"); idx != -1 {
		return address[:idx]
	}
	return address
}

// ValidateAddress validates a gRPC server address for security issues.
// Returns an error if the address contains potentially dangerous patterns.
func ValidateAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	// Reject local file schemes (SSRF prevention)
	lower := strings.ToLower(address)
	if strings.HasPrefix(lower, "file://") ||
		strings.HasPrefix(lower, "unix://") ||
		strings.HasPrefix(lower, "gopher://") {
		return fmt.Errorf("invalid scheme: only grpc:// or direct host:port allowed")
	}

	// Extract hostname for validation
	hostname := extractHostname(address)

	// Reject localhost aliases that could be SSRF
	if hostname == "0.0.0.0" || hostname == "[::]" {
		return fmt.Errorf("invalid address: binding addresses not allowed as targets")
	}

	return nil
}
