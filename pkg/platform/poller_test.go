package platform

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestValidateJob(t *testing.T) {
	defaultConfig := &PollerConfig{}

	tests := []struct {
		name      string
		job       *JobInfo
		config    *PollerConfig
		wantError bool
		errMsg    string
	}{
		{
			name:      "nil job",
			job:       nil,
			config:    defaultConfig,
			wantError: true,
			errMsg:    "job is nil",
		},
		{
			name:      "empty job ID",
			job:       &JobInfo{TenantID: "tenant-1", Type: "scan"},
			config:    defaultConfig,
			wantError: true,
			errMsg:    "job ID is required",
		},
		{
			name:      "empty tenant ID",
			job:       &JobInfo{ID: "job-1", Type: "scan"},
			config:    defaultConfig,
			wantError: true,
			errMsg:    "tenant ID is required",
		},
		{
			name:      "empty job type",
			job:       &JobInfo{ID: "job-1", TenantID: "tenant-1"},
			config:    defaultConfig,
			wantError: true,
			errMsg:    "job type is required",
		},
		{
			name: "disallowed job type",
			job:  &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "malicious"},
			config: &PollerConfig{
				AllowedJobTypes: []string{"scan", "collect"},
			},
			wantError: true,
			errMsg:    "job type \"malicious\" not allowed",
		},
		{
			name: "allowed job type",
			job:  &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan"},
			config: &PollerConfig{
				AllowedJobTypes: []string{"scan", "collect"},
			},
			wantError: false,
		},
		{
			name:      "negative timeout",
			job:       &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan", TimeoutSec: -1},
			config:    defaultConfig,
			wantError: true,
			errMsg:    "negative timeout",
		},
		{
			name:      "timeout too long",
			job:       &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan", TimeoutSec: 7200},
			config:    defaultConfig,
			wantError: true,
			errMsg:    "exceeds maximum",
		},
		{
			name: "missing required auth token",
			job:  &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan"},
			config: &PollerConfig{
				RequireAuthToken: true,
			},
			wantError: true,
			errMsg:    "auth token is required",
		},
		{
			name:      "valid job",
			job:       &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan", TimeoutSec: 300},
			config:    defaultConfig,
			wantError: false,
		},
		{
			name:      "valid job with zero timeout",
			job:       &JobInfo{ID: "job-1", TenantID: "tenant-1", Type: "scan", TimeoutSec: 0},
			config:    defaultConfig,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateJob(tt.job, tt.config)
			if tt.wantError {
				if err == nil {
					t.Errorf("ValidateJob() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateJob() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateJob() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestValidateJob_PayloadSize(t *testing.T) {
	t.Run("payload within limit", func(t *testing.T) {
		job := &JobInfo{
			ID:       "job-1",
			TenantID: "tenant-1",
			Type:     "scan",
			Payload:  map[string]interface{}{"key": "value"},
		}
		config := &PollerConfig{MaxPayloadSize: 1024}

		err := ValidateJob(job, config)
		if err != nil {
			t.Errorf("ValidateJob() unexpected error = %v", err)
		}
	})

	t.Run("payload exceeds limit", func(t *testing.T) {
		// Create large payload
		largeData := make([]byte, 100)
		for i := range largeData {
			largeData[i] = 'x'
		}
		job := &JobInfo{
			ID:       "job-1",
			TenantID: "tenant-1",
			Type:     "scan",
			Payload:  map[string]interface{}{"data": string(largeData)},
		}
		config := &PollerConfig{MaxPayloadSize: 50}

		err := ValidateJob(job, config)
		if err == nil {
			t.Error("ValidateJob() expected error for oversized payload, got nil")
		}
	})
}

func TestValidateTokenTenantClaim(t *testing.T) {
	// Helper to create a mock JWT
	createMockJWT := func(claims map[string]interface{}) string {
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
		payloadBytes, _ := json.Marshal(claims)
		payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
		signature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature"))
		return header + "." + payload + "." + signature
	}

	tests := []struct {
		name             string
		token            string
		expectedTenantID string
		wantError        bool
		errMsg           string
	}{
		{
			name:             "valid token with matching tenant_id",
			token:            createMockJWT(map[string]interface{}{"tenant_id": "tenant-123"}),
			expectedTenantID: "tenant-123",
			wantError:        false,
		},
		{
			name:             "valid token with matching sub claim",
			token:            createMockJWT(map[string]interface{}{"sub": "tenant-123"}),
			expectedTenantID: "tenant-123",
			wantError:        false,
		},
		{
			name:             "token with mismatched tenant_id",
			token:            createMockJWT(map[string]interface{}{"tenant_id": "tenant-456"}),
			expectedTenantID: "tenant-123",
			wantError:        true,
			errMsg:           "does not match",
		},
		{
			name:             "token missing tenant_id claim",
			token:            createMockJWT(map[string]interface{}{"iss": "openctem"}),
			expectedTenantID: "tenant-123",
			wantError:        true,
			errMsg:           "missing tenant_id claim",
		},
		{
			name:             "invalid JWT format - not enough parts",
			token:            "invalid.token",
			expectedTenantID: "tenant-123",
			wantError:        true,
			errMsg:           "invalid JWT format",
		},
		{
			name:             "invalid JWT format - bad base64",
			token:            "header.!!!invalid!!!.signature",
			expectedTenantID: "tenant-123",
			wantError:        true,
			errMsg:           "invalid JWT payload",
		},
		{
			name:             "invalid JWT format - bad JSON",
			token:            "header." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".signature",
			expectedTenantID: "tenant-123",
			wantError:        true,
			errMsg:           "invalid JWT payload JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenTenantClaim(tt.token, tt.expectedTenantID)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateTokenTenantClaim() expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !contains(err.Error(), tt.errMsg) {
					t.Errorf("validateTokenTenantClaim() error = %v, want error containing %q", err, tt.errMsg)
				}
			} else {
				if err != nil {
					t.Errorf("validateTokenTenantClaim() unexpected error = %v", err)
				}
			}
		})
	}
}

func TestJobValidationError(t *testing.T) {
	err := &JobValidationError{
		JobID:  "job-123",
		Reason: "invalid payload",
	}

	expected := "job job-123 validation failed: invalid payload"
	if err.Error() != expected {
		t.Errorf("JobValidationError.Error() = %q, want %q", err.Error(), expected)
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
