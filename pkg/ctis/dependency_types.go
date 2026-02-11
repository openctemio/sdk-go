package ctis

// =============================================================================
// Dependency Types (SBOM)
// =============================================================================

// Dependency represents a software component or library.
type Dependency struct {
	// Unique identifier for this dependency
	ID string `json:"id,omitempty"`

	// Package name
	Name string `json:"name"`

	// Package version
	Version string `json:"version,omitempty"`

	// Package type: library, framework, application, os
	Type string `json:"type,omitempty"`

	// Ecosystem: npm, pypi, maven, gomod, etc.
	Ecosystem string `json:"ecosystem,omitempty"`

	// Package URL (PURL)
	PURL string `json:"purl,omitempty"`

	// Unique identifier from scanner (e.g., Trivy UID)
	UID string `json:"uid,omitempty"`

	// License information
	Licenses []string `json:"licenses,omitempty"`

	// Dependency relationship: direct, indirect, root, transit
	Relationship string `json:"relationship,omitempty"`

	// Dependencies (list of IDs or names this component depends on)
	DependsOn []string `json:"depends_on,omitempty"`

	// File path where this dependency is defined
	Path string `json:"path,omitempty"` // file path

	// Location in file (deprecated, use Locations)
	Location *FindingLocation `json:"location,omitempty"`

	// All locations where this dependency is defined
	Locations []DependencyLocation `json:"locations,omitempty"`
}

// DependencyLocation represents a location where a dependency is defined.
type DependencyLocation struct {
	// File path
	Path string `json:"path,omitempty"`

	// Start line number
	StartLine int `json:"start_line,omitempty"`

	// End line number
	EndLine int `json:"end_line,omitempty"`

	// Start column number
	StartColumn int `json:"start_column,omitempty"`

	// End column number
	EndColumn int `json:"end_column,omitempty"`
}
