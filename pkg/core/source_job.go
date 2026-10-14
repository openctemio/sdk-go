package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	ctissource "github.com/openctemio/ctis/source"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/source"
)

// Code-scan jobs (api RFC-091): a scan command whose payload carries a
// repository source. The executor fetches exactly that commit read-only into
// the sensor's scan workspace (pkg/source), scans the checkout, reports on the
// repository the platform named with the source's branch and commit as a full
// scan, and removes the checkout. The credential, when the source names one,
// is asked from the platform for this command only (SourceCredentials) and
// reaches git alone.

// SourceCredentials fetches the credential of a code-scan command's source
// (the platform client: client.SourceCredential).
type SourceCredentials interface {
	SourceCredential(ctx context.Context, cmdID string) (*source.Credential, error)
}

type sourceCredentialsBox struct{ c SourceCredentials }

// SetSourceCredentials wires the credential fetch of code-scan jobs; without
// it a job whose source names a credential fails.
func (e *DefaultCommandExecutor) SetSourceCredentials(c SourceCredentials) {
	if c == nil {
		e.sourceCreds.Store(nil)
		return
	}
	e.sourceCreds.Store(&sourceCredentialsBox{c: c})
}

// sourceFetchTimeout bounds a fetch inside the job's own time limit.
const sourceFetchTimeout = 10 * time.Minute

// sourceFetcher fetches a repository source (source.Fetcher).
type sourceFetcher interface {
	Fetch(ctx context.Context, repo ctissource.Repository, cred *source.Credential) (*source.Checkout, error)
}

// newSourceFetcher builds the fetcher of a job (replaced in tests).
var newSourceFetcher = func(root string, allowPrivate bool) sourceFetcher {
	return &source.Fetcher{Root: root, AllowPrivate: allowPrivate, Timeout: sourceFetchTimeout}
}

// fetchedSource is a code-scan job's checkout.
type fetchedSource struct {
	checkout   *source.Checkout
	repository string // the asset the findings belong to (the payload's target)
	branch     string
	commit     string
}

func (f *fetchedSource) remove() {
	if f != nil && f.checkout != nil {
		_ = f.checkout.Remove()
	}
}

// annotate marks a report as the full scan of the source's branch and commit.
// The platform overwrites the branch facts from its own branch record; the
// report only says what was scanned.
func (f *fetchedSource) annotate(r *ctis.Report) {
	if f == nil || r == nil {
		return
	}
	r.Metadata.CoverageType = "full"
	r.Metadata.Branch = &ctis.BranchInfo{Name: f.branch, CommitSHA: f.commit}
}

// emptyReport is the report of a full scan that found nothing.
func (f *fetchedSource) emptyReport(tool string) *ctis.Report {
	r := ctis.NewReport()
	r.Tool = &ctis.Tool{Name: tool}
	r.Assets = []ctis.Asset{{ID: "repository", Type: ctis.AssetTypeRepository, Value: f.repository}}
	f.annotate(r)
	return r
}

// fetchSource validates and fetches the payload's source and points the job
// at the checkout. The checkout lives under the first scan-target root, so
// the target policy confines it like any filesystem target; a sensor without
// configured roots refuses code-scan jobs.
func (e *DefaultCommandExecutor) fetchSource(ctx context.Context, cmd *Command, payload *ScanCommandPayload) (*fetchedSource, error) {
	repo := *payload.Source
	if err := repo.Validate(); err != nil {
		return nil, fmt.Errorf("code-scan source refused: %w", err)
	}
	name := strings.TrimSpace(payload.Target)
	if name == "" && len(payload.Targets) == 1 {
		name = strings.TrimSpace(payload.Targets[0])
	}
	if name == "" {
		return nil, errors.New("code-scan job names no repository target")
	}
	policy := e.ScanTargetPolicy()
	if len(policy.AllowedRoots) == 0 {
		return nil, errors.New("code-scan jobs need a confined scan workspace: configure the scan roots")
	}
	var cred *source.Credential
	if repo.Credential != "" {
		box := e.sourceCreds.Load()
		if box == nil {
			return nil, errors.New("code-scan source needs a credential and this sensor cannot ask the platform for one")
		}
		c, err := box.c.SourceCredential(ctx, cmd.ID)
		if err != nil {
			return nil, fmt.Errorf("code-scan source credential: %w", err)
		}
		cred = c
	}
	co, err := newSourceFetcher(policy.AllowedRoots[0], policy.AllowPrivate).Fetch(ctx, repo, cred)
	if err != nil {
		return nil, fmt.Errorf("fetch code-scan source: %w", err)
	}
	payload.Target, payload.Targets = co.Dir, nil
	return &fetchedSource{checkout: co, repository: name, branch: repo.Branch, commit: co.Commit}, nil
}
