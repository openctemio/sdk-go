package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Defaults of Policy.
const (
	DefaultMaxAttempts      = 4
	DefaultBackoffBase      = time.Second
	DefaultBackoffMax       = time.Minute
	DefaultMaxRetryAfter    = 5 * time.Minute
	DefaultAttemptTimeout   = 10 * time.Minute
	DefaultStallTimeout     = time.Minute
	DefaultBreakerThreshold = 3
	DefaultBreakerCooldown  = 5 * time.Minute
)

// Errors.
var (
	// ErrAllOriginsFailed wraps the last error when no origin delivered.
	ErrAllOriginsFailed = errors.New("transfer: every origin failed")
	// ErrBadName: the name is not a single safe path element.
	ErrBadName = errors.New("transfer: invalid file name")
	// ErrTooLarge: the file is larger than allowed or declared.
	ErrTooLarge = errors.New("transfer: file too large")
	// ErrHashMismatch: a blob's bytes do not hash to its name.
	ErrHashMismatch = errors.New("transfer: content hash mismatch")
	// errStalled: no byte arrived within the stall timeout.
	errStalled = errors.New("transfer: download stalled")
)

var (
	nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,200}$`)
	hexRE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Origin is one place files are fetched from: a base URL (file name
// appended after a "/") or, when URL is empty, a local directory (an
// air-gapped upload).
type Origin struct {
	URL  string
	Dir  string
	Name string // label for logs and metrics; default the URL host or "local"
}

func (o Origin) label() string {
	if o.Name != "" {
		return o.Name
	}
	if o.URL == "" {
		return "local"
	}
	if u, err := url.Parse(o.URL); err == nil && u.Host != "" {
		return u.Host
	}
	return "origin"
}

// Policy bounds retries and timeouts. Zero values take the defaults.
type Policy struct {
	// MaxAttempts per origin and file.
	MaxAttempts int
	// BackoffBase and BackoffMax bound the delay between attempts
	// (exponential, jitter in [d/2, d]).
	BackoffBase, BackoffMax time.Duration
	// MaxRetryAfter caps a server's Retry-After; a longer one moves to the
	// next origin instead of waiting.
	MaxRetryAfter time.Duration
	// AttemptTimeout bounds one request, body included.
	AttemptTimeout time.Duration
	// StallTimeout aborts an attempt that received no byte for this long
	// (the next attempt resumes with a Range request).
	StallTimeout time.Duration
	// Overall bounds one Small or Blob call across every origin (0: the
	// caller's context only).
	Overall time.Duration
	// BreakerThreshold consecutive failed files open an origin's circuit
	// for BreakerCooldown.
	BreakerThreshold int
	BreakerCooldown  time.Duration
}

func (p Policy) withDefaults() Policy {
	def := func(v *time.Duration, d time.Duration) {
		if *v <= 0 {
			*v = d
		}
	}
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = DefaultMaxAttempts
	}
	if p.BreakerThreshold <= 0 {
		p.BreakerThreshold = DefaultBreakerThreshold
	}
	def(&p.BackoffBase, DefaultBackoffBase)
	def(&p.BackoffMax, DefaultBackoffMax)
	def(&p.MaxRetryAfter, DefaultMaxRetryAfter)
	def(&p.AttemptTimeout, DefaultAttemptTimeout)
	def(&p.StallTimeout, DefaultStallTimeout)
	def(&p.BreakerCooldown, DefaultBreakerCooldown)
	return p
}

// Config configures a Fetcher.
type Config struct {
	// Origins in the order they are tried. At least one.
	Origins []Origin
	// Client sends every HTTP request. Nil: httpsec.SafeHTTPClient (SSRF
	// guarded). Its own Timeout should be 0: Policy bounds each attempt.
	Client *http.Client
	// CacheDir holds blobs, partial downloads and ETags (0700, files 0600).
	// Required for Blob; optional for Small (no conditional GET without it).
	CacheDir string
	Policy   Policy
	// UserAgent of every request.
	UserAgent string
	// Logger receives retries, resumes and fall-backs. Nil: discarded.
	Logger *slog.Logger

	// sleep waits between attempts (tests replace it).
	sleep func(context.Context, time.Duration) error
	now   func() time.Time
}

// Stats are a Fetcher's counters since it was created.
type Stats struct {
	Fetched     uint64 // files delivered (small and blobs, cache hits excluded)
	Bytes       uint64 // bytes downloaded
	CacheHits   uint64 // blobs served from the cache
	NotModified uint64 // small files answered 304
	Retries     uint64 // attempts after a transient failure
	Resumes     uint64 // Range requests that continued a partial download
	Fallbacks   uint64 // files delivered by an origin other than the first
	Failures    uint64 // files no origin delivered
	CircuitSkip uint64 // origins skipped because their circuit was open
}

// Fetcher fetches files from its origins. It is safe for concurrent use.
type Fetcher struct {
	cfg    Config
	pol    Policy
	client *http.Client
	log    *slog.Logger

	mu      sync.Mutex
	breaker map[int]*circuit

	fetched, bytes, cacheHits, notModified, retries, resumes, fallbacks, failures, circuitSkip atomic.Uint64
}

type circuit struct {
	fails     int
	openUntil time.Time
}

// New returns a Fetcher.
func New(cfg Config) (*Fetcher, error) {
	if len(cfg.Origins) == 0 {
		return nil, errors.New("transfer: no origin")
	}
	for i, o := range cfg.Origins {
		switch {
		case o.URL == "" && o.Dir == "":
			return nil, fmt.Errorf("transfer: origin %d has neither URL nor Dir", i)
		case o.URL != "":
			u, err := url.Parse(o.URL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
				return nil, fmt.Errorf("transfer: origin %d: URL must be http(s) without credentials, query or fragment", i)
			}
		}
	}
	if cfg.Client == nil {
		cfg.Client = httpsec.SafeHTTPClient(0)
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "openctem-transfer/1"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.sleep == nil {
		cfg.sleep = sleepCtx
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.CacheDir != "" {
		for _, d := range []string{cfg.CacheDir, filepath.Join(cfg.CacheDir, "blobs"), filepath.Join(cfg.CacheDir, "tmp"), filepath.Join(cfg.CacheDir, "etag")} {
			if err := os.MkdirAll(d, 0o700); err != nil {
				return nil, fmt.Errorf("transfer: cache: %w", err)
			}
		}
	}
	return &Fetcher{cfg: cfg, pol: cfg.Policy.withDefaults(), client: cfg.Client, log: cfg.Logger, breaker: map[int]*circuit{}}, nil
}

// Stats returns the counters.
func (f *Fetcher) Stats() Stats {
	return Stats{
		Fetched: f.fetched.Load(), Bytes: f.bytes.Load(), CacheHits: f.cacheHits.Load(),
		NotModified: f.notModified.Load(), Retries: f.retries.Load(), Resumes: f.resumes.Load(),
		Fallbacks: f.fallbacks.Load(), Failures: f.failures.Load(), CircuitSkip: f.circuitSkip.Load(),
	}
}

// Small fetches a file of at most maxBytes into memory.
func (f *Fetcher) Small(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return nil, fmt.Errorf("%w: %q", ErrBadName, name)
	}
	var out []byte
	err := f.each(ctx, name, func(ctx context.Context, oi int, o Origin, _ int) error {
		b, err := f.smallOnce(ctx, oi, o, name, maxBytes)
		if err == nil {
			out = b
		}
		return err
	})
	return out, err
}

// Blob returns the path of the verified blob name (lower-case hex sha256 of
// its bytes, size bytes long) in the cache, downloading it when missing.
// The file must not be modified by the caller. Calls for different digests
// may run concurrently; the caller serializes calls for the same digest.
func (f *Fetcher) Blob(ctx context.Context, name, sha256Hex string, size int64) (string, error) {
	if f.cfg.CacheDir == "" {
		return "", errors.New("transfer: Blob needs a CacheDir")
	}
	if !nameRE.MatchString(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("%w: %q", ErrBadName, name)
	}
	if !hexRE.MatchString(sha256Hex) || size < 0 {
		return "", fmt.Errorf("transfer: blob %s: invalid digest or size", name)
	}
	final := f.BlobPath(sha256Hex)
	if fileMatches(final, sha256Hex, size) {
		f.cacheHits.Add(1)
		return final, nil
	}
	_ = os.Remove(final) // a damaged cache entry is fetched again
	part := filepath.Join(f.cfg.CacheDir, "tmp", sha256Hex+".part")
	prevOrigin := -1
	err := f.each(ctx, name, func(ctx context.Context, oi int, o Origin, _ int) error {
		if oi != prevOrigin && prevOrigin >= 0 {
			_ = os.Truncate(part, 0) // never mix bytes of two origins
		}
		prevOrigin = oi
		return f.blobOnce(ctx, o, name, sha256Hex, size, part)
	})
	if err != nil {
		return "", err
	}
	if err := os.Rename(part, final); err != nil {
		return "", fmt.Errorf("transfer: blob %s: %w", name, err)
	}
	syncDir(filepath.Dir(final))
	return final, nil
}

// BlobPath is where the blob with this digest lives in the cache.
func (f *Fetcher) BlobPath(sha256Hex string) string {
	return filepath.Join(f.cfg.CacheDir, "blobs", "sha256-"+sha256Hex)
}

// PruneBlobs removes cached blobs whose digest is not in keep.
func (f *Fetcher) PruneBlobs(keep map[string]bool) (int, error) {
	if f.cfg.CacheDir == "" {
		return 0, nil
	}
	dir := filepath.Join(f.cfg.CacheDir, "blobs")
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		d, ok := strings.CutPrefix(e.Name(), "sha256-")
		if !ok || keep[d] {
			continue
		}
		if os.Remove(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n, nil
}

// each runs try against every origin in order with the retry policy.
func (f *Fetcher) each(ctx context.Context, name string, try func(ctx context.Context, oi int, o Origin, attempt int) error) error {
	if f.pol.Overall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.pol.Overall)
		defer cancel()
	}
	var last error
	for oi, o := range f.cfg.Origins {
		if !f.circuitAllows(oi) {
			f.circuitSkip.Add(1)
			f.log.Warn("transfer: origin circuit open, skipped", "origin", o.label(), "file", name)
			continue
		}
		err := f.tryOrigin(ctx, name, oi, o, try)
		if err == nil {
			f.circuitResult(oi, true)
			f.fetched.Add(1)
			if oi > 0 {
				f.fallbacks.Add(1)
				f.log.Info("transfer: delivered by fall-back origin", "origin", o.label(), "file", name)
			}
			return nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		// Only transient failures count against the origin: a mirror that
		// lacks one file (404) is not unhealthy.
		if te := (*transientError)(nil); errors.As(err, &te) {
			f.circuitResult(oi, false)
		}
		f.log.Warn("transfer: origin failed, trying the next", "origin", o.label(), "file", name, "err", err)
	}
	f.failures.Add(1)
	if last == nil {
		last = errors.New("no origin available")
	}
	if ctx.Err() != nil && !errors.Is(last, ctx.Err()) {
		last = fmt.Errorf("%w (%w)", ctx.Err(), last)
	}
	return fmt.Errorf("%w: %s: %w", ErrAllOriginsFailed, name, last)
}

func (f *Fetcher) tryOrigin(ctx context.Context, name string, oi int, o Origin, try func(context.Context, int, Origin, int) error) error {
	var err error
	for attempt := 1; attempt <= f.pol.MaxAttempts; attempt++ {
		err = try(ctx, oi, o, attempt)
		if err == nil || ctx.Err() != nil {
			return err
		}
		var te *transientError
		if !errors.As(err, &te) {
			return err // permanent for this origin
		}
		if attempt == f.pol.MaxAttempts {
			break
		}
		wait := backoff(f.pol.BackoffBase, f.pol.BackoffMax, attempt)
		if te.retryAfter > 0 {
			if te.retryAfter > f.pol.MaxRetryAfter {
				return fmt.Errorf("retry-after %s exceeds the cap: %w", te.retryAfter, err)
			}
			wait = te.retryAfter
		}
		f.retries.Add(1)
		f.log.Info("transfer: retrying", "origin", o.label(), "file", name, "attempt", attempt+1, "wait", wait, "err", te.err)
		if serr := f.cfg.sleep(ctx, wait); serr != nil {
			return serr
		}
	}
	return err
}

func (f *Fetcher) circuitAllows(oi int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.breaker[oi]
	return c == nil || c.openUntil.IsZero() || !f.cfg.now().Before(c.openUntil)
}

func (f *Fetcher) circuitResult(oi int, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.breaker[oi]
	if c == nil {
		c = &circuit{}
		f.breaker[oi] = c
	}
	if ok {
		*c = circuit{}
		return
	}
	c.fails++
	if c.fails >= f.pol.BreakerThreshold {
		c.openUntil = f.cfg.now().Add(f.pol.BreakerCooldown)
	}
}

// transientError marks a failure worth retrying on the same origin.
type transientError struct {
	err        error
	retryAfter time.Duration
}

func (e *transientError) Error() string { return e.err.Error() }
func (e *transientError) Unwrap() error { return e.err }

func transient(err error) error { return &transientError{err: err} }

// statusErr classifies a non-success HTTP status.
func statusErr(resp *http.Response, now time.Time) error {
	err := fmt.Errorf("http %d", resp.StatusCode)
	switch c := resp.StatusCode; {
	case c == http.StatusRequestTimeout, c == http.StatusTooEarly, c == http.StatusTooManyRequests, c >= 500 && c <= 599:
		return &transientError{err: err, retryAfter: parseRetryAfter(resp.Header.Get("Retry-After"), now)}
	}
	return err
}

func parseRetryAfter(v string, now time.Time) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil {
		if s < 0 {
			return 0
		}
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func backoff(base, maxD time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt && d < maxD; i++ {
		d *= 2
	}
	d = min(d, maxD)
	return d/2 + rand.N(d/2+1) //nolint:gosec // jitter, not security
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func (f *Fetcher) request(ctx context.Context, o Origin, name string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(o.URL, "/")+"/"+url.PathEscape(name), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", f.cfg.UserAgent)
	return req, nil
}

func (f *Fetcher) smallOnce(ctx context.Context, oi int, o Origin, name string, maxBytes int64) ([]byte, error) {
	if o.URL == "" {
		return readLocal(o.Dir, name, maxBytes)
	}
	ctx, cancel := context.WithTimeout(ctx, f.pol.AttemptTimeout)
	defer cancel()
	req, err := f.request(ctx, o, name)
	if err != nil {
		return nil, err
	}
	etagPath, bodyPath := "", ""
	var cached []byte
	if f.cfg.CacheDir != "" {
		key := hex.EncodeToString(sha256Sum([]byte(o.URL + "\x00" + name)))[:32]
		etagPath = filepath.Join(f.cfg.CacheDir, "etag", key+".etag")
		bodyPath = filepath.Join(f.cfg.CacheDir, "etag", key+".body")
		if et, err := os.ReadFile(etagPath); err == nil && len(et) > 0 && len(et) < 512 {
			if b, err := os.ReadFile(bodyPath); err == nil && int64(len(b)) <= maxBytes {
				cached = b
				req.Header.Set("If-None-Match", string(et))
			}
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, transient(err)
	}
	defer drain(resp.Body)
	if resp.StatusCode == http.StatusNotModified && cached != nil {
		f.notModified.Add(1)
		return cached, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, statusErr(resp, f.cfg.now())
	}
	if resp.ContentLength > maxBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes (max %d)", ErrTooLarge, name, resp.ContentLength, maxBytes)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, transient(err)
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, name, maxBytes)
	}
	f.bytes.Add(uint64(len(b))) //nolint:gosec // non-negative
	if et := resp.Header.Get("ETag"); etagPath != "" && et != "" && len(et) < 512 {
		if writeFileAtomic(bodyPath, b) == nil {
			_ = writeFileAtomic(etagPath, []byte(et))
		}
	}
	return b, nil
}

func (f *Fetcher) blobOnce(ctx context.Context, o Origin, name, want string, size int64, part string) error {
	if o.URL == "" {
		return copyLocalBlob(o.Dir, name, want, size, part)
	}
	off := fileSize(part)
	if off > size {
		_ = os.Truncate(part, 0)
		off = 0
	}
	if off < size {
		if err := f.download(ctx, o, name, size, part, off); err != nil {
			return err
		}
	}
	if !fileMatches(part, want, size) {
		_ = os.Remove(part)
		if off > 0 {
			// The resumed tail did not fit the earlier bytes (perhaps from a
			// previous process): start over on the same origin.
			return transient(fmt.Errorf("%w after resume: %s", ErrHashMismatch, name))
		}
		return fmt.Errorf("%w: %s", ErrHashMismatch, name)
	}
	return nil
}

func (f *Fetcher) download(ctx context.Context, o Origin, name string, size int64, part string, off int64) error {
	ctx, cancel := context.WithTimeout(ctx, f.pol.AttemptTimeout)
	defer cancel()
	stallCtx, stall := context.WithCancelCause(ctx)
	defer stall(nil)
	req, err := f.request(stallCtx, o, name)
	if err != nil {
		return err
	}
	if off > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", off))
	}
	timer := time.AfterFunc(f.pol.StallTimeout, func() { stall(errStalled) })
	defer timer.Stop()
	resp, err := f.client.Do(req)
	if err != nil {
		if context.Cause(stallCtx) == errStalled {
			return transient(errStalled)
		}
		return transient(err)
	}
	defer drain(resp.Body)
	flag := os.O_WRONLY | os.O_CREATE
	switch {
	case resp.StatusCode == http.StatusPartialContent && off > 0:
		start, ok := contentRangeStart(resp.Header.Get("Content-Range"))
		if !ok || start != off {
			_ = os.Truncate(part, 0)
			return transient(fmt.Errorf("unexpected Content-Range %q", resp.Header.Get("Content-Range")))
		}
		flag |= os.O_APPEND
		f.resumes.Add(1)
		f.log.Info("transfer: resuming", "origin", o.label(), "file", name, "offset", off)
	case resp.StatusCode == http.StatusOK:
		flag |= os.O_TRUNC
		off = 0
	case resp.StatusCode == http.StatusRequestedRangeNotSatisfiable:
		_ = os.Truncate(part, 0)
		return transient(errors.New("http 416"))
	default:
		return statusErr(resp, f.cfg.now())
	}
	if resp.ContentLength > 0 && off+resp.ContentLength > size {
		return fmt.Errorf("%w: %s is larger than its declared %d bytes", ErrTooLarge, name, size)
	}
	out, err := os.OpenFile(part, flag, 0o600)
	if err != nil {
		return err
	}
	r := &stallReader{r: resp.Body, timer: timer, d: f.pol.StallTimeout}
	n, cerr := io.Copy(out, io.LimitReader(r, size-off+1))
	f.bytes.Add(uint64(max(n, 0))) //nolint:gosec // non-negative
	if serr := out.Sync(); cerr == nil {
		cerr = serr
	}
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	if off+n > size {
		_ = os.Truncate(part, 0)
		return fmt.Errorf("%w: %s is larger than its declared %d bytes", ErrTooLarge, name, size)
	}
	if cerr != nil {
		if context.Cause(stallCtx) == errStalled {
			return transient(errStalled)
		}
		return transient(cerr)
	}
	if off+n < size {
		return transient(fmt.Errorf("short body: %d of %d bytes", off+n, size))
	}
	return nil
}

// stallReader re-arms the stall timer on every read that made progress.
type stallReader struct {
	r     io.Reader
	timer *time.Timer
	d     time.Duration
}

func (s *stallReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	if n > 0 {
		s.timer.Reset(s.d)
	}
	return n, err
}

func contentRangeStart(v string) (int64, bool) {
	v, ok := strings.CutPrefix(v, "bytes ")
	if !ok {
		return 0, false
	}
	dash := strings.IndexByte(v, '-')
	if dash <= 0 {
		return 0, false
	}
	n, err := strconv.ParseInt(v[:dash], 10, 64)
	return n, err == nil
}

func readLocal(dir, name string, maxBytes int64) ([]byte, error) {
	fh, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("%w: %s exceeds %d bytes", ErrTooLarge, name, maxBytes)
	}
	return b, nil
}

func copyLocalBlob(dir, name, want string, size int64, part string) error {
	in, err := os.Open(filepath.Join(dir, name))
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, cerr := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, size+1))
	if err := out.Close(); cerr == nil {
		cerr = err
	}
	switch {
	case cerr != nil:
		return cerr
	case n != size:
		return fmt.Errorf("%w: %s is %d bytes, declared %d", ErrTooLarge, name, n, size)
	case hex.EncodeToString(h.Sum(nil)) != want:
		return fmt.Errorf("%w: %s", ErrHashMismatch, name)
	}
	return nil
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

// fileMatches reports whether path is size bytes hashing to want.
func fileMatches(path, want string, size int64) bool {
	fh, err := os.Open(path)
	if err != nil {
		return false
	}
	defer fh.Close()
	if st, err := fh.Stat(); err != nil || st.Size() != size || !st.Mode().IsRegular() {
		return false
	}
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return false
	}
	return hex.EncodeToString(h.Sum(nil)) == want
}

func sha256Sum(b []byte) []byte { s := sha256.Sum256(b); return s[:] }

func drain(rc io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(rc, 64<<10))
	_ = rc.Close()
}

// writeFileAtomic writes b to path (0600) through a synced temporary file.
func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	_, werr := tmp.Write(b)
	if err := tmp.Sync(); werr == nil {
		werr = err
	}
	if err := tmp.Close(); werr == nil {
		werr = err
	}
	if werr == nil {
		werr = os.Chmod(tmp.Name(), 0o600)
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), path)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return werr
	}
	syncDir(filepath.Dir(path))
	return nil
}

// WriteFileAtomic writes b to path (0600) crash-safely: a synced temporary
// file renamed over path, then the directory synced.
func WriteFileAtomic(path string, b []byte) error { return writeFileAtomic(path, b) }

func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
