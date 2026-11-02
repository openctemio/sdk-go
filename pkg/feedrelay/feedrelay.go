// Package feedrelay is the sensor side of the feed relay (api RFC-142): a
// platform with no outbound access receives its signed feeds through a
// platform-owned sensor that has internet access.
//
// The sensor is a pipe for files and adds no trust. The platform plans what
// it needs and sends a round: a feed name, the feed origins the files come
// from, and the files by name (each with a size cap, and a SHA-256 and size
// pin when the platform already knows them from a verified manifest). The
// round is signed by the platform's job signer (command type feed_relay,
// the platform tenant id, instance scope); the sensor verifies it with the
// job-signing keys it pins, downloads each file from <origin>/<name>, and
// streams it back. The platform verifies every file against the feed's own
// pinned root before anything is applied.
//
// What bounds the sensor, whatever the platform asks:
//   - only a shared sensor relays (the round's signature must verify for the
//     instance scope and this sensor);
//   - every origin must be in the sensor's own allowlist (the official feed
//     origins plus SENSOR_FEED_RELAY_ORIGINS set by the host operator);
//   - names are single path segments of a fixed grammar;
//   - downloads go through the SSRF-guarded client (public addresses only,
//     redirects re-checked) with a size cap per file and per round, to a
//     temporary file, never into memory beyond one file;
//   - a pinned file whose digest or size differs is never uploaded.
//
// Stability: Beta (docs/STABILITY.md).
package feedrelay

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

// Capability is what a sensor that relays feeds reports.
const Capability = "feed.relay@1"

// Paths below the sensor API prefix (/api/v2/sensor).
const (
	NextPath  = "/feed-relay/next"
	RoundPath = "/feed-relay/" // + {round}/files/{name} | {round}/done
)

// Limits.
const (
	MaxOrigins    = 8
	MaxFiles      = 512
	MaxFileBytes  = 64 << 20
	MaxRoundBytes = 1 << 30
	// MaxRoundBody caps the next-round response (payload + signed job).
	MaxRoundBody = 1 << 20
)

// Outcome statuses of one file.
const (
	StatusOK       = "ok"
	StatusNotFound = "not_found"
	StatusRefused  = "refused"
	StatusError    = "error"
)

// DefaultOrigins are the official feed origins every relay may fetch from.
var DefaultOrigins = []string{
	"https://github.com/openctemio/vulnfeed-bundles/releases/latest/download",
	"https://github.com/openctemio/openctem/releases/latest/download",
}

var (
	nameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	feedRe   = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// File is one file a round asks for.
type File struct {
	Name string `json:"name"`
	// SHA256 and Size pin the file when the platform knows them (lower-case
	// hex); a pinned file whose bytes differ is not uploaded.
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size,omitempty"`
	// MaxBytes caps the download.
	MaxBytes int64 `json:"max_bytes"`
}

// Payload is a round's signed payload. Targets are the feed origins (they
// are the statement's targets, which the signer checked against its own
// allowlist).
type Payload struct {
	Feed    string   `json:"feed"`
	Targets []string `json:"targets"`
	Files   []File   `json:"files"`
}

// Round is what GET next returns.
type Round struct {
	ID        string          `json:"id"`
	Payload   json.RawMessage `json:"payload"`
	SignedJob json.RawMessage `json:"signed_job"`
}

// Outcome is the result of one file.
type Outcome struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	// Code is a short reason for a file not delivered (never upstream text).
	Code   string `json:"code,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Report is the body of POST done.
type Report struct {
	Files []Outcome `json:"files"`
	// Refused is set when the whole round was refused (a bad signature, an
	// origin outside the allowlist); Files is then empty.
	Refused string `json:"refused,omitempty"`
}

// Platform is the sensor's connection to the platform (pkg/client.Client).
type Platform interface {
	// NextFeedRelay returns the next round, or nil and the platform's
	// Retry-After (0: none) when there is none.
	NextFeedRelay(ctx context.Context) (*Round, time.Duration, error)
	// UploadFeedRelayFile streams one file of a round.
	UploadFeedRelayFile(ctx context.Context, roundID, name string, body io.Reader, size int64, sha256Hex string) error
	// FeedRelayDone reports the round.
	FeedRelayDone(ctx context.Context, roundID string, rep Report) error
}

// Verifier verifies a round's signed statement (core.JobGuard of a shared
// sensor).
type Verifier interface {
	VerifyFeedRelay(ctx context.Context, roundID string, payload, signedJob []byte) (*jobsig.Statement, error)
}

// Config configures a Relay.
type Config struct {
	Platform Platform
	Verifier Verifier
	// Origins is the allowlist (canonical spelling, NormalizeOrigin).
	Origins []string
	// HTTP downloads the files: an SSRF-guarded client
	// (httpsec.SafeHTTPClient).
	HTTP *http.Client
	// Dir holds the temporary files (the sensor's state directory).
	Dir string
	// Interval between polls (default 60 s).
	Interval time.Duration
	// Logf logs one line (nil: discarded).
	Logf func(format string, args ...any)
}

// Relay polls for rounds and serves them.
type Relay struct {
	cfg     Config
	allowed map[string]bool
}

// New checks the configuration.
func New(cfg Config) (*Relay, error) {
	if cfg.Platform == nil || cfg.Verifier == nil || cfg.HTTP == nil {
		return nil, errors.New("feedrelay: a platform connection, a verifier and an HTTP client are required")
	}
	if cfg.Dir == "" {
		return nil, errors.New("feedrelay: a directory for temporary files is required")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Minute
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	r := &Relay{cfg: cfg, allowed: map[string]bool{}}
	for _, o := range cfg.Origins {
		n := NormalizeOrigin(o)
		if n == "" {
			return nil, fmt.Errorf("feedrelay: origin %q is not an https origin without credentials, query or fragment", o)
		}
		r.allowed[n] = true
	}
	if len(r.allowed) == 0 {
		return nil, errors.New("feedrelay: no feed origin is allowed")
	}
	return r, nil
}

// NormalizeOrigin returns the canonical spelling of a feed origin, or ""
// when s is not one: an absolute https URL with a host, no user info, query
// or fragment, no dot segments; scheme and host lower-cased, no trailing
// slash. It matches the platform signer's spelling.
func NormalizeOrigin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 1024 || strings.ContainsAny(s, " \t\r\n\\") {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return ""
	}
	if strings.Contains(u.Path, "/../") || strings.HasSuffix(u.Path, "/..") || strings.Contains(u.Path, "/./") {
		return ""
	}
	return "https://" + strings.ToLower(u.Host) + strings.TrimRight(u.EscapedPath(), "/")
}

// ParseOrigins returns the allowlist: DefaultOrigins plus the
// comma-separated extra origins of the host (SENSOR_FEED_RELAY_ORIGINS).
func ParseOrigins(extra string) ([]string, error) {
	out := append([]string(nil), DefaultOrigins...)
	for _, p := range strings.Split(extra, ",") {
		if strings.TrimSpace(p) == "" {
			continue
		}
		n := NormalizeOrigin(p)
		if n == "" {
			return nil, fmt.Errorf("feed relay origin %q is not an https origin without credentials, query or fragment", strings.TrimSpace(p))
		}
		out = append(out, n)
	}
	return out, nil
}

// Run polls until ctx ends.
func (r *Relay) Run(ctx context.Context) {
	t := time.NewTimer(0)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		served, wait, err := r.runOnce(ctx)
		if err != nil && ctx.Err() == nil {
			r.cfg.Logf("feed relay: %v", err)
		}
		t.Reset(r.nextPoll(served, wait, err))
	}
}

// Poll bounds: the platform's Retry-After is honored within them.
const (
	minPoll = time.Second
	maxPoll = 30 * time.Minute
	// refusedPoll is the wait after the platform refused this sensor (403):
	// not designated is answered 204 with a Retry-After, so a 403 means it
	// may not relay at all (not a platform sensor, or disabled).
	refusedPoll = 15 * time.Minute
)

// retryAfter is an error that carries the server's Retry-After
// (client.HTTPError on 429 and 503).
type retryAfter interface{ RetryAfterHint() time.Duration }

// statusCoder is an error that carries an HTTP status (client.HTTPError).
type statusCoder interface{ HTTPStatusCode() int }

// nextPoll is how long to wait before asking again: right after a served
// round soon (the platform plans the next one), else the platform's
// Retry-After when it sent one, else the interval; a refused sensor waits
// long.
func (r *Relay) nextPoll(served bool, wait time.Duration, err error) time.Duration {
	var ra retryAfter
	var sc statusCoder
	switch {
	case errors.As(err, &ra) && ra.RetryAfterHint() > 0:
		wait = ra.RetryAfterHint()
	case errors.As(err, &sc) && sc.HTTPStatusCode() == http.StatusForbidden:
		wait = refusedPoll
	case served:
		return minPoll
	}
	if wait <= 0 {
		return r.cfg.Interval
	}
	return min(max(wait, minPoll), maxPoll)
}

// RunOnce asks for one round and serves it. served reports whether a round
// was handled (delivered or refused).
func (r *Relay) RunOnce(ctx context.Context) (served bool, err error) {
	served, _, err = r.runOnce(ctx)
	return served, err
}

func (r *Relay) runOnce(ctx context.Context) (served bool, wait time.Duration, err error) {
	round, wait, err := r.cfg.Platform.NextFeedRelay(ctx)
	if err != nil || round == nil {
		return false, wait, err
	}
	p, err := r.admit(ctx, round)
	if err != nil {
		r.cfg.Logf("feed relay: round %s refused: %v", round.ID, err)
		code := "refused"
		if jobsig.ReasonOf(err) != "" {
			code = "signature_" + jobsig.ReasonOf(err)
		}
		return true, 0, r.cfg.Platform.FeedRelayDone(ctx, round.ID, Report{Refused: code})
	}
	rep := Report{Files: make([]Outcome, 0, len(p.Files))}
	var total int64
	for _, f := range p.Files {
		if ctx.Err() != nil {
			return true, 0, ctx.Err()
		}
		o := r.serveFile(ctx, round.ID, p.Targets, f, MaxRoundBytes-total)
		total += o.Bytes
		rep.Files = append(rep.Files, o)
	}
	return true, 0, r.cfg.Platform.FeedRelayDone(ctx, round.ID, rep)
}

// admit verifies the round's signature and checks its payload against the
// sensor's own rules.
func (r *Relay) admit(ctx context.Context, round *Round) (*Payload, error) {
	if round.ID == "" || len(round.ID) > 64 {
		return nil, errors.New("round id missing or too long")
	}
	if _, err := r.cfg.Verifier.VerifyFeedRelay(ctx, round.ID, round.Payload, round.SignedJob); err != nil {
		return nil, err
	}
	var p Payload
	dec := json.NewDecoder(bytes.NewReader(round.Payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	if !feedRe.MatchString(p.Feed) {
		return nil, errors.New("payload: bad feed name")
	}
	if len(p.Targets) == 0 || len(p.Targets) > MaxOrigins {
		return nil, fmt.Errorf("payload: 1 to %d origins", MaxOrigins)
	}
	for _, o := range p.Targets {
		if NormalizeOrigin(o) != o || !r.allowed[o] {
			return nil, fmt.Errorf("origin %q is not in this sensor's feed relay allowlist (SENSOR_FEED_RELAY_ORIGINS)", o)
		}
	}
	if len(p.Files) == 0 || len(p.Files) > MaxFiles {
		return nil, fmt.Errorf("payload: 1 to %d files", MaxFiles)
	}
	seen := map[string]bool{}
	var total int64
	for _, f := range p.Files {
		switch {
		case !nameRe.MatchString(f.Name) || f.Name == "." || f.Name == "..":
			return nil, fmt.Errorf("payload: bad file name %q", f.Name)
		case seen[f.Name]:
			return nil, fmt.Errorf("payload: file %q listed twice", f.Name)
		case f.MaxBytes <= 0 || f.MaxBytes > MaxFileBytes:
			return nil, fmt.Errorf("payload: file %q cap must be 1 to %d bytes", f.Name, MaxFileBytes)
		case f.SHA256 != "" && !sha256Re.MatchString(f.SHA256):
			return nil, fmt.Errorf("payload: file %q has a bad sha256 pin", f.Name)
		case f.Size < 0 || f.Size > f.MaxBytes:
			return nil, fmt.Errorf("payload: file %q size pin is over its cap", f.Name)
		}
		seen[f.Name] = true
		total += f.MaxBytes
	}
	if total > MaxRoundBytes*2 {
		return nil, errors.New("payload: the round asks for too much")
	}
	return &p, nil
}

// serveFile downloads one file from the first origin that delivers it
// intact, then uploads it.
func (r *Relay) serveFile(ctx context.Context, roundID string, origins []string, f File, budget int64) Outcome {
	o := Outcome{Name: f.Name, Status: StatusNotFound, Code: "not_found"}
	limit := min(f.MaxBytes, budget)
	if limit <= 0 {
		return Outcome{Name: f.Name, Status: StatusRefused, Code: "round_budget"}
	}
	for _, origin := range origins {
		path, size, sum, code := r.download(ctx, origin+"/"+f.Name, limit)
		if code == "" && ((f.SHA256 != "" && sum != f.SHA256) || (f.Size > 0 && size != f.Size)) {
			_ = os.Remove(path)
			code = "refused_pin_mismatch"
		}
		if code != "" {
			// A later origin may hold the file intact; keep the most telling
			// reason (refused over error over not found).
			if rank(statusOf(code)) > rank(o.Status) {
				o = Outcome{Name: f.Name, Status: statusOf(code), Code: code}
			}
			continue
		}
		err := r.upload(ctx, roundID, f.Name, path, size, sum)
		_ = os.Remove(path)
		if err != nil {
			r.cfg.Logf("feed relay: upload of %s failed: %v", f.Name, err)
			return Outcome{Name: f.Name, Status: StatusError, Code: "upload_failed"}
		}
		return Outcome{Name: f.Name, Status: StatusOK, Bytes: size, SHA256: sum}
	}
	return o
}

func rank(status string) int {
	switch status {
	case StatusRefused:
		return 3
	case StatusError:
		return 2
	}
	return 1
}

func statusOf(code string) string {
	switch {
	case code == "not_found":
		return StatusNotFound
	case strings.HasPrefix(code, "refused_"):
		return StatusRefused
	}
	return StatusError
}

// download streams url into a temporary file under the cap and returns its
// path, size and SHA-256, or a short code.
func (r *Relay) download(ctx context.Context, rawURL string, limit int64) (path string, size int64, sum string, code string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", 0, "", "bad_url"
	}
	req.Header.Set("Accept", "*/*")
	resp, err := r.cfg.HTTP.Do(req)
	if err != nil {
		return "", 0, "", "unreachable"
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", 0, "", "not_found"
	case resp.StatusCode != http.StatusOK:
		return "", 0, "", fmt.Sprintf("http_%d", resp.StatusCode)
	case resp.ContentLength > limit:
		return "", 0, "", "refused_too_large"
	}
	tmp, err := os.CreateTemp(r.cfg.Dir, ".feedrelay-*")
	if err != nil {
		return "", 0, "", "temp_file"
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(resp.Body, limit+1))
	cerr := tmp.Close()
	switch {
	case err != nil || cerr != nil:
		_ = os.Remove(tmp.Name())
		return "", 0, "", "read_failed"
	case n > limit:
		_ = os.Remove(tmp.Name())
		return "", 0, "", "refused_too_large"
	}
	return tmp.Name(), n, hex.EncodeToString(h.Sum(nil)), ""
}

func (r *Relay) upload(ctx context.Context, roundID, name, path string, size int64, sum string) error {
	f, err := os.Open(path) //nolint:gosec // our own temporary file
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return r.cfg.Platform.UploadFeedRelayFile(ctx, roundID, name, f, size, sum)
}
