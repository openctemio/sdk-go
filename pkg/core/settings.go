package core

// Tool settings: what a tool lets an administrator configure, declared as a
// small JSON Schema in its tool manifest, and the layered values a scan runs
// with. The contract (schema subset, validator, defaults, digest, layers,
// common tool options) lives in github.com/openctemio/ctis/settings so the
// platform validates values with the same code as the sensor; these are
// aliases kept for the SDK's callers. See api RFC-038.

import (
	"github.com/openctemio/ctis/settings"
)

// Limits of a settings schema.
const (
	MaxSettingsSchemaBytes = settings.MaxSchemaBytes
	MaxSettingsProperties  = settings.MaxProperties
	MaxSettingsEnum        = settings.MaxEnum
	MaxSettingsPatternLen  = settings.MaxPatternLen
	MaxSettingsStringLen   = settings.MaxStringLen
	MaxSettingsItems       = settings.MaxItems
)

type (
	// SettingScope is the lowest level allowed to set a key.
	SettingScope = settings.Scope
	// SettingSource is where an effective value came from.
	SettingSource = settings.Source
	// SettingsSchemaError is why a schema is invalid.
	SettingsSchemaError = settings.SchemaError
	// SettingsError is one invalid value.
	SettingsError = settings.Error
	// SettingsErrors is every problem of a values document.
	SettingsErrors = settings.Errors
	// SettingProperty is one key of a schema.
	SettingProperty = settings.Property
	// SettingsSchema is a tool's parsed settings schema.
	SettingsSchema = settings.Schema
	// SettingsLayer is one level of values.
	SettingsLayer = settings.Layer
	// ToolSettings are a tool's effective settings for one scan.
	ToolSettings = settings.Values
)

// Setting scopes and sources.
const (
	SettingScopeSensor   = settings.ScopeSensor
	SettingScopeScan     = settings.ScopeScan
	SettingSourceDefault = settings.SourceDefault
	SettingSourceTenant  = settings.SourceTenant
	SettingSourceSensor  = settings.SourceSensor
	SettingSourceProfile = settings.SourceProfile
	SettingSourceScan    = settings.SourceScan
	SettingSourceJob     = settings.SourceJob
)

// ParseSettingsSchema parses and checks a schema (settings.ParseSchema).
func ParseSettingsSchema(raw []byte) (*SettingsSchema, error) { return settings.ParseSchema(raw) }

// MustParseSettingsSchema is ParseSettingsSchema for a schema compiled into
// the binary; it panics on an invalid schema.
func MustParseSettingsSchema(raw string) *SettingsSchema { return settings.MustParseSchema(raw) }

// SettingsDigest is the canonical digest of a values document.
func SettingsDigest(raw []byte) (string, error) { return settings.DocumentDigest(raw) }

// manifestSettings is what the manifest carries for a schema: its version
// and digest, never the schema itself.
func manifestSettings(s *SettingsSchema) *ManifestToolSettings {
	if s == nil {
		return nil
	}
	return &ManifestToolSettings{SchemaVersion: s.Version, Digest: s.Digest()}
}

// isSettingName reports whether k is a well-formed setting name.
func isSettingName(k string) bool { return settings.ValidName(k) }
