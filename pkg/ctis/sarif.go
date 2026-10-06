package ctis

import "strings"

// SARIFLog is the root SARIF document. It is the module's SARIFLog with the
// SDK's SARIFRun, which also reads versionControlProvenance.
type SARIFLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema,omitempty"`
	Runs    []SARIFRun `json:"runs"`
}

// SARIFRun is a single run of a tool: the module's SARIFRun plus
// VersionControlProvenance. The nested SARIF types are the module's.
type SARIFRun struct {
	Tool        SARIFTool         `json:"tool"`
	Results     []SARIFResult     `json:"results"`
	Artifacts   []SARIFArtifact   `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation `json:"invocations,omitempty"`

	// VersionControlProvenance names the repository and revision the run
	// analyzed (SARIF 2.1.0 §3.14.17). GitHub code scanning and CodeQL
	// emit it.
	VersionControlProvenance []SARIFVersionControlDetails `json:"versionControlProvenance,omitempty"`
}

// SARIFVersionControlDetails is a SARIF versionControlDetails object.
type SARIFVersionControlDetails struct {
	RepositoryURI string `json:"repositoryUri"`
	RevisionID    string `json:"revisionId,omitempty"`
	Branch        string `json:"branch,omitempty"`
}

// Repository returns the first repository named in the run's
// versionControlProvenance, with its revision and branch, or empty strings.
func (r *SARIFRun) Repository() (uri, revision, branch string) {
	for _, vc := range r.VersionControlProvenance {
		if u := strings.TrimSpace(vc.RepositoryURI); u != "" {
			return u, vc.RevisionID, vc.Branch
		}
	}
	return "", "", ""
}
