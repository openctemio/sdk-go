package github

import (
	"testing"

	"github.com/openctemio/sdk-go/pkg/connectors/github" //nolint:staticcheck // deprecated together with this package
)

func TestRepoAsset_SCMRepoID(t *testing.T) {
	a := repoAsset(github.Repository{ID: 123456789, Name: "api", FullName: "acme/api"}, "acme")
	if a.Identifiers == nil || a.Identifiers.SCMRepoID != "123456789" {
		t.Fatalf("expected scm_repo_id 123456789, got %+v", a.Identifiers)
	}
	if a.Value != "acme/api" || a.Technical.Repository.Owner != "acme" {
		t.Fatalf("existing fields changed: %+v", a)
	}

	if b := repoAsset(github.Repository{Name: "x", FullName: "acme/x"}, "acme"); b.Identifiers != nil {
		t.Fatalf("a repository without an ID must not get identifiers, got %+v", b.Identifiers)
	}
}
