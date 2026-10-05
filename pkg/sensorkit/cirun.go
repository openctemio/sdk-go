package sensorkit

// Runner mode with CI workload identity (api RFC-051): a CI job proves who it
// is with its CI provider's OIDC token (GitHub Actions, GitLab CI) and
// exchanges it for a short-lived run token bound to one run on one
// repository. No API key is stored in CI. The run token never leaves this
// type: it is not printed, not logged and not part of any error.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

// Environment variables of runner mode.
const (
	// EnvTenantID turns OIDC on: the organization whose CI trust admits the job.
	EnvTenantID = "OPENCTEM_TENANT_ID"
	// EnvOIDCAudience overrides the audience (default openctem:tenant:<id>).
	EnvOIDCAudience = "OPENCTEM_OIDC_AUDIENCE"
	// EnvIDTokenVar names the GitLab id_tokens variable (default
	// OPENCTEM_ID_TOKEN).
	EnvIDTokenVar = "OPENCTEM_ID_TOKEN_VAR"
	// DefaultIDTokenVar is the GitLab id_tokens variable read by default.
	DefaultIDTokenVar = "OPENCTEM_ID_TOKEN"
)

// CI providers runner mode can get an OIDC token from.
const (
	CIProviderGitHub = "github"
	CIProviderGitLab = "gitlab"
)

// ErrNoCIOIDC: the environment offers no CI OIDC token (no tenant set, not
// in GitHub Actions with id-token: write, no GitLab id_tokens variable).
var ErrNoCIOIDC = errors.New("no CI OIDC token available")

// ErrCIExchangeRefused: the platform did not accept the job's OIDC token.
var ErrCIExchangeRefused = errors.New("the platform did not accept the CI token")

// renewBefore re-exchanges (GitHub only) when the run token expires sooner.
const renewBefore = 2 * time.Minute

// maxErrBody bounds an error response read.
const maxErrBody = 4 << 10

// CIRunConfig configures runner mode. Zero fields are read from the
// environment (CIRunConfigFromEnv).
type CIRunConfig struct {
	// APIURL is the platform's URL (API_URL).
	APIURL string
	// TenantID is the organization (OPENCTEM_TENANT_ID).
	TenantID string
	// Audience defaults to openctem:tenant:<TenantID>.
	Audience string
	// IDTokenVar is the GitLab id_tokens variable (OPENCTEM_ID_TOKEN).
	IDTokenVar string
	// HTTPClient makes every request (default: 30s timeout).
	HTTPClient *http.Client
	// Getenv reads the environment (default os.Getenv; tests replace it).
	Getenv func(string) string
}

// CIRunConfigFromEnv fills a configuration from the environment.
func CIRunConfigFromEnv() CIRunConfig {
	return CIRunConfig{APIURL: os.Getenv("API_URL"), TenantID: os.Getenv(EnvTenantID),
		Audience: os.Getenv(EnvOIDCAudience), IDTokenVar: os.Getenv(EnvIDTokenVar)}
}

func (c *CIRunConfig) normalize() {
	if c.Getenv == nil {
		c.Getenv = os.Getenv
	}
	c.APIURL = strings.TrimRight(strings.TrimSpace(c.APIURL), "/")
	c.TenantID = strings.TrimSpace(c.TenantID)
	if c.Audience == "" && c.TenantID != "" {
		c.Audience = "openctem:tenant:" + c.TenantID
	}
	if c.IDTokenVar == "" {
		c.IDTokenVar = DefaultIDTokenVar
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
}

// DetectCIOIDC reports which CI provider can give this job an OIDC token.
func DetectCIOIDC(cfg CIRunConfig) (string, bool) {
	cfg.normalize()
	if cfg.TenantID == "" {
		return "", false
	}
	if cfg.Getenv("GITHUB_ACTIONS") == "true" && cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL") != "" &&
		cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN") != "" {
		return CIProviderGitHub, true
	}
	if cfg.Getenv("GITLAB_CI") == "true" && cfg.Getenv(cfg.IDTokenVar) != "" {
		return CIProviderGitLab, true
	}
	return "", false
}

// CIRun is one CI run on the platform. It implements core.Pusher, so a
// one-shot runner can push its reports through it. The token is obtained
// at the first use (after the scans, so the 15-minute token covers the
// uploads and the verdict).
type CIRun struct {
	cfg      CIRunConfig
	provider string

	mu        sync.Mutex
	runID     string
	token     string
	expiresAt time.Time
	info      CIRunInfo
	usedGL    bool
}

var _ core.Pusher = (*CIRun)(nil)

// CIRunInfo is what the platform says about the run.
type CIRunInfo struct {
	RunID           string `json:"run_id"`
	Repository      string `json:"repository"`
	Branch          string `json:"branch"`
	CommitSHA       string `json:"commit_sha"`
	PullRequest     string `json:"pull_request"`
	DefaultBranch   string `json:"default_branch"`
	IsDefaultBranch bool   `json:"is_default_branch"`
}

// NewCIRun returns a run for this CI job, or ErrNoCIOIDC when the job has no
// OIDC token to offer (the caller then falls back to an API key).
func NewCIRun(cfg CIRunConfig) (*CIRun, error) {
	cfg.normalize()
	provider, ok := DetectCIOIDC(cfg)
	if !ok {
		return nil, ErrNoCIOIDC
	}
	if cfg.APIURL == "" {
		return nil, errors.New("API_URL is required for runner mode")
	}
	if u, err := url.Parse(cfg.APIURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, errors.New("API_URL must be an http(s) URL")
	}
	return &CIRun{cfg: cfg, provider: provider}, nil
}

// Provider is the CI provider the run authenticates with.
func (r *CIRun) Provider() string { return r.provider }

// Info is the run as the platform registered it (empty before Open).
func (r *CIRun) Info() CIRunInfo {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info
}

// String never shows the token.
func (r *CIRun) String() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return fmt.Sprintf("CIRun{provider=%s run=%s token=[redacted]}", r.provider, r.runID)
}

// Open exchanges the job's OIDC token for a run token, once; later calls
// renew it (GitHub) when it is about to expire.
func (r *CIRun) Open(ctx context.Context) error {
	_, err := r.bearer(ctx)
	return err
}

// bearer returns a valid run token, exchanging or renewing as needed.
func (r *CIRun) bearer(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" && time.Until(r.expiresAt) > renewBefore {
		return r.token, nil
	}
	if r.token != "" && r.provider != CIProviderGitHub {
		// A GitLab ID token is good for one exchange: keep the current run
		// token until it expires.
		if time.Now().Before(r.expiresAt) {
			return r.token, nil
		}
		return "", errors.New("the CI run token expired and GitLab offers no second OIDC token: upload and evaluate within 15 minutes of the first upload")
	}
	idToken, err := r.idToken(ctx)
	if err != nil {
		return "", err
	}
	body := map[string]string{"tenant_id": r.cfg.TenantID, "id_token": idToken}
	if r.runID != "" {
		body["run_id"] = r.runID
	}
	var out struct {
		CIRunInfo
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := r.do(ctx, "", "/api/v1/ci/oidc/exchange", body, &out); err != nil {
		var se *ciStatusError
		if errors.As(err, &se) && se.status == http.StatusUnauthorized {
			return "", fmt.Errorf("%w: %s (check the CI trust configuration, the audience %q and that the token is used once)",
				ErrCIExchangeRefused, se.message, r.cfg.Audience)
		}
		return "", fmt.Errorf("CI token exchange: %w", err)
	}
	if !strings.HasPrefix(out.Token, "octci_") || out.RunID == "" {
		return "", errors.New("CI token exchange: unexpected response")
	}
	r.token, r.expiresAt, r.runID, r.info = out.Token, out.ExpiresAt, out.RunID, out.CIRunInfo
	return r.token, nil
}

// idToken asks the CI provider for the job's OIDC token.
func (r *CIRun) idToken(ctx context.Context) (string, error) {
	switch r.provider {
	case CIProviderGitHub:
		reqURL := r.cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
		u, err := url.Parse(reqURL)
		if err != nil || u.Host == "" {
			return "", errors.New("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
		}
		q := u.Query()
		q.Set("audience", r.cfg.Audience)
		u.RawQuery = q.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Authorization", "bearer "+r.cfg.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
		req.Header.Set("Accept", "application/json")
		resp, err := r.cfg.HTTPClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("request the GitHub OIDC token: %w", scrubURL(err))
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
			return "", fmt.Errorf("request the GitHub OIDC token: status %d (does the workflow grant id-token: write?)", resp.StatusCode)
		}
		var out struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil || out.Value == "" {
			return "", errors.New("request the GitHub OIDC token: no token in the response")
		}
		return out.Value, nil
	case CIProviderGitLab:
		if r.usedGL {
			return "", errors.New("the GitLab ID token was already exchanged")
		}
		r.usedGL = true
		return r.cfg.Getenv(r.cfg.IDTokenVar), nil
	}
	return "", ErrNoCIOIDC
}

// ciStatusError is an HTTP error from the platform: status and the
// platform's message only.
type ciStatusError struct {
	status  int
	message string
}

func (e *ciStatusError) Error() string {
	if e.message == "" {
		return fmt.Sprintf("status %d", e.status)
	}
	return fmt.Sprintf("status %d: %s", e.status, e.message)
}

// do sends a JSON request to the platform. The bearer is never part of an
// error.
func (r *CIRun) do(ctx context.Context, bearer, path string, body, out any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.cfg.APIURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", useragent.String())
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return scrubURL(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
		var e struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Message
		if e.Code != "" && msg != "" {
			msg = e.Code + ": " + msg
		}
		return &ciStatusError{status: resp.StatusCode, message: sanitize(msg)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrBody))
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
}

// call runs an authenticated request on the run (the token is renewed first
// when it is about to expire).
func (r *CIRun) call(ctx context.Context, action string, body, out any) error {
	tok, err := r.bearer(ctx)
	if err != nil {
		return err
	}
	r.mu.Lock()
	path := "/api/v1/ci/runs/" + url.PathEscape(r.runID) + "/" + action
	r.mu.Unlock()
	return r.do(ctx, tok, path, body, out)
}

// PushFindings uploads a report to the run (core.Pusher).
func (r *CIRun) PushFindings(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	if report == nil {
		return &core.PushResult{Success: true}, nil
	}
	var out struct {
		FindingsCreated int `json:"findings_created"`
		FindingsUpdated int `json:"findings_updated"`
		AssetsCreated   int `json:"assets_created"`
		AssetsUpdated   int `json:"assets_updated"`
	}
	if err := r.call(ctx, "results", map[string]any{"report": report}, &out); err != nil {
		return nil, fmt.Errorf("upload results: %w", err)
	}
	return &core.PushResult{Success: true, FindingsCreated: out.FindingsCreated, FindingsUpdated: out.FindingsUpdated,
		AssetsCreated: out.AssetsCreated, AssetsUpdated: out.AssetsUpdated}, nil
}

// PushAssets uploads a report to the run (core.Pusher).
func (r *CIRun) PushAssets(ctx context.Context, report *ctis.Report) (*core.PushResult, error) {
	return r.PushFindings(ctx, report)
}

// SendHeartbeat does nothing: a CI run is not a sensor (core.Pusher).
func (r *CIRun) SendHeartbeat(context.Context, *core.SensorStatus) error { return nil }

// TestConnection does nothing: the run is opened at the first upload, after
// the scans, so its 15-minute token covers the uploads (core.Pusher).
func (r *CIRun) TestConnection(context.Context) error { return nil }

// BaselineDiff returns the fingerprints not already open on the default
// branch.
func (r *CIRun) BaselineDiff(ctx context.Context, fingerprints []string) ([]string, error) {
	var out struct {
		New []string `json:"new"`
	}
	if err := r.call(ctx, "baseline-diff", map[string]any{"fingerprints": fingerprints}, &out); err != nil {
		return nil, fmt.Errorf("baseline diff: %w", err)
	}
	return out.New, nil
}

// CIVerdict is the platform's gate verdict for the run.
type CIVerdict struct {
	RunID     string `json:"run_id"`
	Verdict   string `json:"verdict"`
	WouldFail bool   `json:"would_fail"`
	Reasons   []struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		Title     string `json:"title,omitempty"`
		Severity  string `json:"severity,omitempty"`
		File      string `json:"file,omitempty"`
		Line      int    `json:"line,omitempty"`
		URL       string `json:"url,omitempty"`
		FindingID string `json:"finding_id,omitempty"`
	} `json:"reasons"`
	Summary struct {
		Evaluated   int `json:"evaluated"`
		New         int `json:"new"`
		PreExisting int `json:"pre_existing"`
		Accepted    int `json:"accepted"`
		Blocking    int `json:"blocking"`
	} `json:"summary"`
	Policy struct {
		Source string `json:"source"`
		Mode   string `json:"mode"`
	} `json:"policy"`
	Baseline struct {
		Branch string `json:"branch"`
		Known  bool   `json:"known"`
	} `json:"baseline"`
	Links struct {
		Run      string `json:"run"`
		Findings string `json:"findings"`
	} `json:"links"`
}

// Failed reports whether the pipeline must fail.
func (v *CIVerdict) Failed() bool { return v != nil && v.Verdict == "fail" }

// Evaluate asks the platform's gate for the run's verdict. scanFailures is
// the number of scanners that failed to run or to report: any fails the run.
func (r *CIRun) Evaluate(ctx context.Context, scanFailures int) (*CIVerdict, error) {
	var v CIVerdict
	if err := r.call(ctx, "evaluate", map[string]int{"scan_failures": scanFailures}, &v); err != nil {
		return nil, fmt.Errorf("evaluate: %w", err)
	}
	return &v, nil
}

// WriteVerdict prints a verdict for a pipeline log.
func WriteVerdict(w io.Writer, v *CIVerdict) {
	if v == nil {
		return
	}
	state := "PASS"
	switch {
	case v.Failed():
		state = "FAIL"
	case v.WouldFail:
		state = "PASS (break-glass or warn mode; it would fail)"
	}
	_, _ = fmt.Fprintf(w, "\nOpenCTEM gate: %s (policy: %s)\n", state, v.Policy.Source)
	_, _ = fmt.Fprintf(w, "  %d judged: %d new, %d already on %s, %d accepted, %d blocking\n",
		v.Summary.Evaluated, v.Summary.New, v.Summary.PreExisting, nonEmpty(v.Baseline.Branch, "the default branch"),
		v.Summary.Accepted, v.Summary.Blocking)
	for _, rs := range v.Reasons {
		where := ""
		if rs.File != "" {
			where = " " + rs.File
			if rs.Line > 0 {
				where += fmt.Sprintf(":%d", rs.Line)
			}
		}
		title := rs.Title
		if title == "" {
			title = rs.Message
		} else {
			title += ": " + rs.Message
		}
		_, _ = fmt.Fprintf(w, "  - [%s]%s %s\n", rs.Code, where, sanitize(title))
	}
	if v.Links.Run != "" {
		_, _ = fmt.Fprintf(w, "  Run: %s\n", v.Links.Run)
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

// sanitize strips control characters from platform text before printing.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// scrubURL drops the request URL from a transport error: a GitHub token
// request URL carries a query the log does not need.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}
