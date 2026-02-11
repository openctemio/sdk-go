package core

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors.
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}
	var msgs []string
	for _, err := range e {
		msgs = append(msgs, err.Error())
	}
	return fmt.Sprintf("validation failed: %s", strings.Join(msgs, "; "))
}

// HasErrors returns true if there are any errors.
func (e ValidationErrors) HasErrors() bool {
	return len(e) > 0
}

// Add adds a validation error.
func (e *ValidationErrors) Add(field, message string) {
	*e = append(*e, ValidationError{Field: field, Message: message})
}

// Validator provides validation methods for configurations.
type Validator struct {
	errors ValidationErrors
}

// NewValidator creates a new validator.
func NewValidator() *Validator {
	return &Validator{}
}

// Required validates that a field is not empty.
func (v *Validator) Required(field, value string) *Validator {
	if strings.TrimSpace(value) == "" {
		v.errors.Add(field, "is required")
	}
	return v
}

// URL validates that a field is a valid URL.
func (v *Validator) URL(field, value string) *Validator {
	if value == "" {
		return v
	}
	u, err := url.Parse(value)
	if err != nil {
		v.errors.Add(field, fmt.Sprintf("invalid URL: %v", err))
		return v
	}
	if u.Scheme == "" || u.Host == "" {
		v.errors.Add(field, "must be a valid URL with scheme and host")
	}
	return v
}

// MinDuration validates that a duration is at least the minimum.
func (v *Validator) MinDuration(field string, value, min time.Duration) *Validator {
	if value < min {
		v.errors.Add(field, fmt.Sprintf("must be at least %v", min))
	}
	return v
}

// MaxDuration validates that a duration is at most the maximum.
func (v *Validator) MaxDuration(field string, value, max time.Duration) *Validator {
	if value > max {
		v.errors.Add(field, fmt.Sprintf("must be at most %v", max))
	}
	return v
}

// Min validates that an integer is at least the minimum.
func (v *Validator) Min(field string, value, min int) *Validator {
	if value < min {
		v.errors.Add(field, fmt.Sprintf("must be at least %d", min))
	}
	return v
}

// Max validates that an integer is at most the maximum.
func (v *Validator) Max(field string, value, max int) *Validator {
	if value > max {
		v.errors.Add(field, fmt.Sprintf("must be at most %d", max))
	}
	return v
}

// OneOf validates that a value is one of the allowed values.
func (v *Validator) OneOf(field, value string, allowed []string) *Validator {
	if value == "" {
		return v
	}
	for _, a := range allowed {
		if value == a {
			return v
		}
	}
	v.errors.Add(field, fmt.Sprintf("must be one of: %s", strings.Join(allowed, ", ")))
	return v
}

// DirectoryExists validates that a directory exists.
func (v *Validator) DirectoryExists(field, path string) *Validator {
	if path == "" {
		return v
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		v.errors.Add(field, "directory does not exist")
		return v
	}
	if err != nil {
		v.errors.Add(field, fmt.Sprintf("cannot access directory: %v", err))
		return v
	}
	if !info.IsDir() {
		v.errors.Add(field, "is not a directory")
	}
	return v
}

// FileExists validates that a file exists.
func (v *Validator) FileExists(field, path string) *Validator {
	if path == "" {
		return v
	}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		v.errors.Add(field, "file does not exist")
		return v
	}
	if err != nil {
		v.errors.Add(field, fmt.Sprintf("cannot access file: %v", err))
		return v
	}
	if info.IsDir() {
		v.errors.Add(field, "is a directory, expected file")
	}
	return v
}

// APIKey validates an API key format.
func (v *Validator) APIKey(field, value string) *Validator {
	if value == "" {
		return v
	}
	// OpenCTEM API keys should start with rs_ prefix
	validPrefixes := []string{"rs_src_", "rs_usr_", "rs_int_"}
	for _, prefix := range validPrefixes {
		if strings.HasPrefix(value, prefix) {
			return v
		}
	}
	v.errors.Add(field, "invalid API key format (should start with rs_src_, rs_usr_, or rs_int_)")
	return v
}

// SourceID validates a source ID format.
func (v *Validator) SourceID(field, value string) *Validator {
	if value == "" {
		return v
	}
	if !strings.HasPrefix(value, "src_") {
		v.errors.Add(field, "invalid source ID format (should start with src_)")
	}
	return v
}

// Custom adds a custom validation check.
func (v *Validator) Custom(field string, check func() bool, message string) *Validator {
	if !check() {
		v.errors.Add(field, message)
	}
	return v
}

// Errors returns all validation errors.
func (v *Validator) Errors() ValidationErrors {
	return v.errors
}

// Validate returns an error if there are validation errors.
func (v *Validator) Validate() error {
	if v.errors.HasErrors() {
		return v.errors
	}
	return nil
}

// =============================================================================
// Config Validation Functions
// =============================================================================

// ValidateBaseScannerConfig validates a BaseScannerConfig.
func ValidateBaseScannerConfig(cfg *BaseScannerConfig) error {
	v := NewValidator()
	v.Required("name", cfg.Name)
	v.Required("binary", cfg.Binary)
	if cfg.Timeout != 0 {
		v.MinDuration("timeout", cfg.Timeout, 1*time.Second)
		v.MaxDuration("timeout", cfg.Timeout, 24*time.Hour)
	}
	return v.Validate()
}

// ValidateBaseAgentConfig validates a BaseAgentConfig.
func ValidateBaseAgentConfig(cfg *BaseAgentConfig) error {
	v := NewValidator()
	v.Required("name", cfg.Name)
	if cfg.ScanInterval != 0 {
		v.MinDuration("scan_interval", cfg.ScanInterval, 1*time.Minute)
	}
	if cfg.HeartbeatInterval != 0 {
		v.MinDuration("heartbeat_interval", cfg.HeartbeatInterval, 10*time.Second)
		v.MaxDuration("heartbeat_interval", cfg.HeartbeatInterval, 1*time.Hour)
	}
	return v.Validate()
}

// ValidateCommandPollerConfig validates a CommandPollerConfig.
func ValidateCommandPollerConfig(cfg *CommandPollerConfig) error {
	v := NewValidator()
	if cfg.PollInterval != 0 {
		v.MinDuration("poll_interval", cfg.PollInterval, 5*time.Second)
		v.MaxDuration("poll_interval", cfg.PollInterval, 1*time.Hour)
	}
	if cfg.MaxConcurrent != 0 {
		v.Min("max_concurrent", cfg.MaxConcurrent, 1)
		v.Max("max_concurrent", cfg.MaxConcurrent, 100)
	}
	return v.Validate()
}

// ValidateScanOptions validates ScanOptions.
func ValidateScanOptions(opts *ScanOptions) error {
	if opts == nil {
		return nil
	}
	v := NewValidator()
	if opts.TargetDir != "" {
		v.DirectoryExists("target_dir", opts.TargetDir)
	}
	if opts.ConfigFile != "" {
		v.FileExists("config_file", opts.ConfigFile)
	}
	return v.Validate()
}
