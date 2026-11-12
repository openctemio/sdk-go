// Package ctlog answers Certificate Transparency lookups (capability
// lookup.ct@1, contract package ctlookup) for a platform that makes no
// request to a CT source itself: a platform-owned sensor runs them.
//
// One lookup asks crt.sh for the certificates of a root domain and the names
// under it, and falls back to Cert Spotter when crt.sh keeps failing. What
// keeps it polite and robust:
//
//   - each source has its own pace (one request per interval, shared by
//     every lookup of the process) and a cool-down after a 429 or a
//     Retry-After (at most 15 minutes: it is shared by every organization
//     the sensor serves), so a busy sensor does not hammer a source;
//   - crt.sh may use only part of a lookup's time (all but a share of at
//     least 25 s or 30 %, at most half), so a slow crt.sh still leaves Cert
//     Spotter its turn and the lookup an answer listing both source states;
//   - crt.sh gets a few attempts with jittered exponential back-off, and a
//     server's Retry-After is honored within a bound;
//   - every response body is capped and read as a stream, one row at a time:
//     an answer over the byte cap or over ctlookup.MaxRecords rows is refused
//     as a whole (StateTooLarge) as soon as the cap is passed, never read in
//     full and never taken as a truncated list; one row is capped too
//     (maxRowBytes), so a single giant row is refused the same way, and the
//     names of a row are cut at ctlookup.MaxNamesPerRecord while they are
//     read; an empty body is a bad answer, not "no certificates" (crt.sh
//     answers [] for none);
//   - a source failure is a SourceStatus entry of the answer, never an
//     error: the lookup itself fails only on a bad input or a canceled
//     context;
//   - an answer with at least one source ok, or whose every source is
//     too_large (a definite answer too: the list is over a cap), is cached
//     per (tenant, domain, cursor) for about 20 hours, so a retried job does
//     not query again; a source's too_large is also remembered on its own,
//     so a big domain does not cost Cert Spotter's paced requests to a
//     per-address quota at every lookup while crt.sh is still retried; the
//     cache is never shared across tenants, so one tenant's timing cannot
//     reveal another's watch list;
//   - the answer passes ctlookup.Validate before it leaves: names bound to
//     the queried domain, a leading wildcard label kept, bounds held.
//
// The HTTP client is the caller's: on a sensor it is the SSRF-guarded client
// (httpsec.SafeHTTPClient), which honors the sensor's proxy.
//
// Stability: Beta (docs/STABILITY.md).
package ctlog

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/contract/ctlookup"
)

// Defaults.
const (
	DefaultCRTSHURL       = "https://crt.sh"
	DefaultCertSpotterURL = "https://api.certspotter.com"
	// DefaultMaxBodyBytes caps one response body. crt.sh answers for a
	// large domain run to tens of MiB.
	DefaultMaxBodyBytes = 48 << 20
	// DefaultInterval is the least time between two requests to one source.
	DefaultInterval = time.Second
	// DefaultCacheTTL is how long an answer is reused for the same tenant,
	// domain and cursor.
	DefaultCacheTTL = 20 * time.Hour
	// DefaultCacheBytes bounds the answers kept (encoded size).
	DefaultCacheBytes = 64 << 20
	// DefaultTimeout bounds one HTTP request (crt.sh may take a minute on a
	// large domain).
	DefaultTimeout = 90 * time.Second
	// DefaultHeaderTimeout is the wait for a source's response headers.
	// crt.sh sends them only once its query is done, which takes longer
	// than a general client's 15 s on a large domain; the lookup's budget
	// (crt.sh's share of it) still bounds the wait.
	DefaultHeaderTimeout = 75 * time.Second
)

const (
	crtshAttempts = 3
	retryBase     = 2 * time.Second
	retryCap      = 30 * time.Second
	maxRetryAfter = 60 * time.Second
	// maxCoolDown bounds how long one source is left alone after a 429 or a
	// Retry-After. The cool-down is shared by every organization the sensor
	// serves (the quota is per address), so a source that asks for a day must
	// not switch CT monitoring off for a day for all of them.
	maxCoolDown = 15 * time.Minute
	// fallbackReserve is the least share of a lookup's time left for Cert
	// Spotter when crt.sh is slow (the share is at least 30 % of the time
	// left, and never more than half of it).
	fallbackReserve     = 25 * time.Second
	certSpotterMaxPages = 10
	// maxRowBytes caps one row of an answer (a crt.sh row or a Cert Spotter
	// issuance). A real certificate row is a few KiB; the contract keeps at
	// most 1000 names of 253 bytes per record, about 250 KiB. A row over the
	// cap makes the answer too_large, so one giant row is never held whole.
	maxRowBytes = 2 << 20
	// tooLargeCacheBytes bounds the remembered too_large states (about
	// 60 bytes each).
	tooLargeCacheBytes = 1 << 20
	// maxPaceWait is the longest a lookup waits for its turn at a source;
	// a source cooling down for longer is reported rate_limited at once.
	maxPaceWait = 60 * time.Second
)

// Config configures a Client.
type Config struct {
	// HTTP performs the requests (required): the SSRF-guarded client.
	HTTP *http.Client
	// CRTSHURL and CertSpotterURL are the sources' base URLs (default the
	// public services; a host operator may point them at a mirror, never
	// the platform). CertSpotterOff turns the fallback off.
	CRTSHURL       string
	CertSpotterURL string
	CertSpotterOff bool
	// CertSpotterKey returns the Cert Spotter key ("" none: the free
	// unauthenticated quota). Sent only to the Cert Spotter base URL.
	CertSpotterKey func() string
	// UserAgent of the requests (default "openctem-ctlog").
	UserAgent string
	// MaxBodyBytes, Interval, CacheTTL, CacheBytes: see the defaults.
	MaxBodyBytes int64
	Interval     time.Duration
	CacheTTL     time.Duration
	CacheBytes   int64

	// now, sleep and fallbackMin are replaced by tests.
	now         func() time.Time
	sleep       func(ctx context.Context, d time.Duration) error
	fallbackMin time.Duration
}

// Client runs CT lookups. It is safe for concurrent use.
type Client struct {
	cfg   Config
	crtsh *pacer
	cs    *pacer
	cache *cache
	// tooLarge remembers per (tenant, domain, cursor, source) a source
	// that answered too_large; its own map, so its keys never meet the
	// answers'.
	tooLarge *cache
}

// New checks the configuration and returns a Client.
func New(cfg Config) (*Client, error) {
	if cfg.HTTP == nil {
		return nil, errors.New("ctlog: an HTTP client is required")
	}
	if cfg.CRTSHURL == "" {
		cfg.CRTSHURL = DefaultCRTSHURL
	}
	if cfg.CertSpotterURL == "" {
		cfg.CertSpotterURL = DefaultCertSpotterURL
	}
	for _, u := range []string{cfg.CRTSHURL, cfg.CertSpotterURL} {
		p, err := url.Parse(u)
		if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || p.User != nil || p.RawQuery != "" {
			return nil, fmt.Errorf("ctlog: source %q is not a base URL", u)
		}
	}
	if cfg.UserAgent == "" {
		cfg.UserAgent = "openctem-ctlog"
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultCacheTTL
	}
	if cfg.CacheBytes <= 0 {
		cfg.CacheBytes = DefaultCacheBytes
	}
	if cfg.now == nil {
		cfg.now = time.Now
	}
	if cfg.sleep == nil {
		cfg.sleep = sleepCtx
	}
	if cfg.fallbackMin <= 0 {
		cfg.fallbackMin = fallbackReserve
	}
	c := &Client{cfg: cfg, cache: newCache(cfg.CacheBytes), tooLarge: newCache(tooLargeCacheBytes)}
	c.crtsh = &pacer{interval: cfg.Interval, now: cfg.now}
	c.cs = &pacer{interval: cfg.Interval, now: cfg.now}
	return c, nil
}

// Lookup answers one lookup for tenant (the organization the job is for;
// the cache key, never shared). The error is non-nil only for an invalid
// input or a done context; every source failure is in the answer's
// source_status.
func (c *Client) Lookup(ctx context.Context, tenant string, in ctlookup.Input) (ctlookup.Output, error) {
	in, err := ctlookup.CheckInput(in)
	if err != nil {
		return ctlookup.Output{}, err
	}
	key := tenant + "\x00" + in.Domain + "\x00" + in.After
	if out, ok := c.cache.get(key, c.cfg.now()); ok {
		return out, nil
	}

	var out ctlookup.Output
	// crt.sh may use the lookup's time only up to a point: Cert Spotter keeps
	// a share, so a slow crt.sh cannot leave the lookup with no answer.
	recs, st, known := c.tooLargeBefore(key, ctlookup.SourceCRTSH)
	if !known {
		crtCtx, stop := c.crtshContext(ctx)
		recs, st = c.queryCRTSH(crtCtx, in.Domain)
		stop()
		if err := ctx.Err(); err != nil {
			return ctlookup.Output{}, err
		}
	}
	out.SourceStatus = append(out.SourceStatus, st)
	if st.State == ctlookup.StateOK {
		out.Records = recs
	} else if !c.cfg.CertSpotterOff {
		recs, st, known = c.tooLargeBefore(key, ctlookup.SourceCertSpotter)
		if !known {
			recs, st = c.queryCertSpotter(ctx, in.Domain, in.After)
			if err := ctx.Err(); err != nil {
				return ctlookup.Output{}, err
			}
		}
		out.SourceStatus = append(out.SourceStatus, st)
		if st.State == ctlookup.StateOK {
			out.Records = recs
		}
	}
	if out.Records == nil {
		out.Records = []ctlookup.Record{}
	}
	clean, _, err := ctlookup.Validate(in.Domain, out)
	if err != nil {
		// Only reachable through a bug here: never send what the contract
		// refuses.
		return ctlookup.Output{}, fmt.Errorf("ctlog: answer breaks the contract: %w", err)
	}
	clean = capSize(clean)
	expires := c.cfg.now().Add(c.cfg.CacheTTL)
	if cacheable(clean) {
		c.cache.put(key, clean, expires)
	}
	// A source whose list is over a cap stays so for the cache's lifetime:
	// remember it per source, so the next lookup asks only the sources that
	// may answer (a big domain does not cost Cert Spotter's eleven paced
	// requests again while crt.sh is still retried).
	for _, s := range clean.SourceStatus {
		if s.State == ctlookup.StateTooLarge {
			c.tooLarge.put(sourceKey(key, s.Source), ctlookup.Output{SourceStatus: []ctlookup.SourceStatus{s}}, expires)
		}
	}
	return clean, nil
}

func sourceKey(key, source string) string { return key + "\x00" + source }

// tooLargeBefore returns the source's too_large status when it is
// remembered for this tenant, domain and cursor.
func (c *Client) tooLargeBefore(key, source string) ([]ctlookup.Record, ctlookup.SourceStatus, bool) {
	if out, ok := c.tooLarge.get(sourceKey(key, source), c.cfg.now()); ok && len(out.SourceStatus) == 1 {
		return nil, out.SourceStatus[0], true
	}
	return nil, ctlookup.SourceStatus{}, false
}

// cacheable tells a definite answer: a source answered ok, or every source
// that was asked answered too_large. A too_large list stays too large for
// the cache's lifetime, and asking again would cost up to eleven paced
// requests to a per-address quota for the same answer. A failure that may
// pass (unavailable, rate_limited) is never cached.
func cacheable(out ctlookup.Output) bool {
	tooLarge := 0
	for _, s := range out.SourceStatus {
		switch s.State {
		case ctlookup.StateOK:
			return true
		case ctlookup.StateTooLarge:
			tooLarge++
		}
	}
	return tooLarge > 0 && tooLarge == len(out.SourceStatus)
}

// crtshContext bounds the crt.sh part of a lookup: it ends early enough to
// leave Cert Spotter a share of the time the lookup has (see splitBudget). A
// lookup with no deadline, or with no fallback, is not bounded further.
func (c *Client) crtshContext(ctx context.Context) (context.Context, context.CancelFunc) {
	dl, ok := ctx.Deadline()
	if !ok || c.cfg.CertSpotterOff {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, splitBudget(time.Until(dl), c.cfg.fallbackMin))
}

// splitBudget is the time crt.sh may use of the remaining time of a lookup:
// what is left after the fallback's share, which is at least minReserve and
// at least 30 % of the remaining time, but never more than half of it.
func splitBudget(remaining, minReserve time.Duration) time.Duration {
	reserve := max(minReserve, remaining*3/10)
	reserve = min(reserve, remaining/2)
	return max(remaining-reserve, 0)
}

// capSize turns an answer whose encoding is over the contract's bound into
// a too_large answer for the source that produced the records.
func capSize(out ctlookup.Output) ctlookup.Output {
	b, err := json.Marshal(out)
	if err == nil && len(b) <= ctlookup.MaxOutputBytes {
		return out
	}
	out.Records = []ctlookup.Record{}
	for i := range out.SourceStatus {
		if out.SourceStatus[i].State == ctlookup.StateOK {
			out.SourceStatus[i].State = ctlookup.StateTooLarge
		}
	}
	return out
}

// crtshEntry is one row of crt.sh's JSON answer.
type crtshEntry struct {
	ID           json.Number `json:"id"`
	IssuerName   string      `json:"issuer_name"`
	CommonName   string      `json:"common_name"`
	NameValue    string      `json:"name_value"`
	SerialNumber string      `json:"serial_number"`
	NotBefore    string      `json:"not_before"`
	NotAfter     string      `json:"not_after"`
}

// queryCRTSH asks crt.sh with up to crtshAttempts tries on a retryable
// failure.
func (c *Client) queryCRTSH(ctx context.Context, domain string) ([]ctlookup.Record, ctlookup.SourceStatus) {
	u, _ := url.Parse(c.cfg.CRTSHURL)
	u.Path = strings.TrimRight(u.Path, "/") + "/"
	q := url.Values{}
	// "%.<domain>": the domain and every name under it (SQL LIKE).
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	// One row per certificate, not a precertificate and certificate pair.
	q.Set("deduplicate", "Y")
	u.RawQuery = q.Encode()

	var last error
	for attempt := 0; attempt < crtshAttempts; attempt++ {
		if attempt > 0 {
			if err := c.cfg.sleep(ctx, retryDelay(attempt, last)); err != nil {
				return nil, unavailable(ctlookup.SourceCRTSH)
			}
		}
		var recs []ctlookup.Record
		err := c.get(ctx, c.crtsh, ctlookup.SourceCRTSH, u.String(), nil, func(r io.Reader) (perr error) {
			recs, perr = parseCRTSH(r)
			return perr
		})
		if err == nil {
			return recs, ctlookup.SourceStatus{Source: ctlookup.SourceCRTSH, State: ctlookup.StateOK}
		}
		last = err
		if st, final := finalStatus(ctlookup.SourceCRTSH, err); final {
			return nil, st
		}
		if ctx.Err() != nil {
			break
		}
	}
	st, _ := finalStatus(ctlookup.SourceCRTSH, last)
	if st.State == "" {
		st = unavailable(ctlookup.SourceCRTSH)
	}
	return nil, st
}

// parseCRTSH reads crt.sh's JSON array one row at a time, so a hostile
// answer never sits in memory whole: it stops at the record cap. A row that
// does not decode, an empty body or anything but a list makes the whole
// answer unusable (crt.sh answers "[]" for no certificates, a bare array
// otherwise, or an error page).
func parseCRTSH(r io.Reader) ([]ctlookup.Record, error) {
	out := []ctlookup.Record{}
	err := decodeArray(r, ctlookup.MaxRecords, func(e crtshEntry) {
		// SplitN: the cut happens while splitting, so a row of many short
		// names never becomes a slice of all of them.
		names := strings.SplitN(e.NameValue, "\n", ctlookup.MaxNamesPerRecord+1)
		if e.CommonName != "" {
			names = append(names, e.CommonName)
		}
		if len(names) > ctlookup.MaxNamesPerRecord {
			names = names[:ctlookup.MaxNamesPerRecord]
		}
		out = append(out, ctlookup.Record{
			Source: ctlookup.SourceCRTSH, EntryID: clipField(e.ID.String()), DNSNames: names,
			Issuer: clipField(e.IssuerName), Serial: clipField(e.SerialNumber),
			NotBefore: ctlookup.FormatTime(parseTime(e.NotBefore)), NotAfter: ctlookup.FormatTime(parseTime(e.NotAfter)),
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// decodeArray decodes the JSON array in r one element at a time and calls
// each with it. It stops with errTooMany at the first element past limit,
// without reading further. A body that is empty, not an array or not valid
// JSON is errBadAnswer; an error of the reader itself (a cut connection, the
// size cap) is returned as it is.
func decodeArray[T any](r io.Reader, limit int, each func(T)) error {
	cr, ok := r.(*capReader)
	if !ok {
		cr = &capReader{r: r, max: -1}
	}
	bad := func(what string, err error) error {
		if cr.err != nil {
			return cr.err
		}
		return fmt.Errorf("%w: %s: %w", errBadAnswer, what, err)
	}
	dec := json.NewDecoder(cr)
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return bad("answer is not a JSON list", err)
	}
	if d, isDelim := tok.(json.Delim); !isDelim || d != '[' {
		return fmt.Errorf("%w: answer is not a JSON list", errBadAnswer)
	}
	n := 0
	for dec.More() {
		if n >= limit {
			return errTooMany
		}
		var v T
		// The row starts at the decoder's offset: what the reader hands out
		// past it, for this row, is capped at maxRowBytes.
		cr.startRow(dec.InputOffset())
		err := dec.Decode(&v)
		cr.endRow()
		if err != nil {
			return bad("row does not decode", err)
		}
		n++
		each(v)
	}
	if _, err := dec.Token(); err != nil {
		return bad("list is not closed", err)
	}
	// The size cap holds for the whole body: read what follows the list
	// (nothing, for a well-formed answer) within the same cap.
	if _, err := io.Copy(io.Discard, cr); err != nil {
		return err
	}
	return nil
}

// capReader reads r, at most max bytes (max < 0: no cap); past the cap Read
// fails with errTooLarge. Between startRow and endRow it also hands out at
// most maxRowBytes past the row's start, and fails with errTooLarge when the
// decoder asks for more: one row is never read whole past that cap. Any
// other error of r is kept in err, so a caller tells a cut connection from a
// body that is not valid.
type capReader struct {
	r   io.Reader
	max int64
	n   int64
	err error

	inRow    bool
	rowStart int64
}

// startRow starts the per-row cap at offset off of the body (the decoder's
// position before the row: bytes it already holds past off count).
func (c *capReader) startRow(off int64) { c.inRow, c.rowStart = true, off }

func (c *capReader) endRow() { c.inRow = false }

func (c *capReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	if c.inRow {
		// One byte past the row cap may be handed out; the decoder asking
		// for more after that means the row is longer than the cap.
		left := c.rowStart + maxRowBytes + 1 - c.n
		if left <= 0 {
			c.err = fmt.Errorf("%w (a row over %d bytes)", errTooLarge, maxRowBytes)
			return 0, c.err
		}
		if int64(len(p)) > left {
			p = p[:left]
		}
	}
	if c.max >= 0 {
		// One byte more than the cap is read, so an over-long body shows.
		if left := c.max + 1 - c.n; int64(len(p)) > left {
			p = p[:left]
		}
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	if c.max >= 0 && c.n > c.max {
		c.err = fmt.Errorf("%w (%d bytes)", errTooLarge, c.max)
		return n - int(c.n-c.max), c.err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		c.err = err
	}
	return n, err
}

// certSpotterIssuance is one record of Cert Spotter's /v1/issuances answer
// with expand=dns_names and expand=issuer.
type certSpotterIssuance struct {
	ID        string   `json:"id"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Issuer    struct {
		FriendlyName string `json:"friendly_name"`
		Name         string `json:"name"`
	} `json:"issuer"`
	CertSHA256 string `json:"cert_sha256"`
}

// queryCertSpotter lists the unexpired issuances of domain and the names
// under it, at most certSpotterMaxPages pages, from after on. The list ends
// at an empty page (the API's only end marker: its page size is neither
// fixed nor documented, so a short page is not taken as the end). After the
// last page one more is asked: empty, the list was complete; not empty, the
// list is cut and too_large.
func (c *Client) queryCertSpotter(ctx context.Context, domain, after string) ([]ctlookup.Record, ctlookup.SourceStatus) {
	base, _ := url.Parse(c.cfg.CertSpotterURL)
	base.Path = strings.TrimRight(base.Path, "/") + "/v1/issuances"
	var hdr http.Header
	if c.cfg.CertSpotterKey != nil {
		if k := strings.TrimSpace(c.cfg.CertSpotterKey()); k != "" {
			hdr = http.Header{"Authorization": {"Bearer " + k}}
		}
	}
	out := []ctlookup.Record{}
	for page := 0; page <= certSpotterMaxPages; page++ {
		q := url.Values{}
		q.Set("domain", domain)
		q.Set("include_subdomains", "true")
		q.Add("expand", "dns_names")
		q.Add("expand", "issuer")
		if after != "" {
			q.Set("after", after)
		}
		u := *base
		u.RawQuery = q.Encode()
		var lastID string
		got := 0
		err := c.get(ctx, c.cs, ctlookup.SourceCertSpotter, u.String(), hdr, func(r io.Reader) error {
			// One issuance at a time, the record cap counted over all pages:
			// a hostile page is never held whole.
			return decodeArray(r, ctlookup.MaxRecords-len(out), func(it certSpotterIssuance) {
				issuer := it.Issuer.FriendlyName
				if issuer == "" {
					issuer = it.Issuer.Name
				}
				// The row is capped at maxRowBytes while it is read, which
				// bounds this list; only the first names are kept.
				names := it.DNSNames
				if len(names) > ctlookup.MaxNamesPerRecord {
					names = names[:ctlookup.MaxNamesPerRecord:ctlookup.MaxNamesPerRecord]
				}
				out = append(out, ctlookup.Record{
					Source: ctlookup.SourceCertSpotter, EntryID: clipField(it.ID), DNSNames: names,
					Issuer: clipField(issuer), Serial: clipField(it.CertSHA256),
					NotBefore: ctlookup.FormatTime(parseTime(it.NotBefore)), NotAfter: ctlookup.FormatTime(parseTime(it.NotAfter)),
				})
				lastID = it.ID
				got++
			})
		})
		if err != nil {
			st, _ := finalStatus(ctlookup.SourceCertSpotter, err)
			if st.State == "" {
				st = unavailable(ctlookup.SourceCertSpotter)
			}
			return nil, st
		}
		if got == 0 || lastID == "" {
			// An empty page, or no cursor to continue from: what was listed
			// is all there is.
			return out, ctlookup.SourceStatus{Source: ctlookup.SourceCertSpotter, State: ctlookup.StateOK}
		}
		after = lastID
	}
	// The page after the last one was not empty: the list is cut. A cut list would read as names that vanished, so none
	// of it is used (the contract's rule for an answer over a cap).
	return nil, ctlookup.SourceStatus{Source: ctlookup.SourceCertSpotter, State: ctlookup.StateTooLarge}
}

// Errors of one request.
var (
	errBadAnswer = errors.New("bad answer")
	errTooLarge  = errors.New("answer over the size cap")
	errTooMany   = errors.New("answer over the record cap")
)

// statusError is a non-200 answer.
type statusError struct {
	code       int
	retryAfter time.Duration
}

func (e *statusError) Error() string { return "HTTP " + strconv.Itoa(e.code) }

// rateLimited is a source cooling down (its own 429 or Retry-After, or the
// pace of this process).
type rateLimited struct{ wait time.Duration }

func (e *rateLimited) Error() string { return "rate limited" }

// finalStatus maps a request error to a source status; final is true when
// a retry cannot help (429, a 4xx, an answer over a cap).
func finalStatus(source string, err error) (ctlookup.SourceStatus, bool) {
	var se *statusError
	var rl *rateLimited
	switch {
	case err == nil:
		return ctlookup.SourceStatus{}, false
	case errors.As(err, &rl):
		return ctlookup.SourceStatus{Source: source, State: ctlookup.StateRateLimited, RetryAfterS: seconds(rl.wait)}, true
	case errors.Is(err, errTooLarge), errors.Is(err, errTooMany):
		return ctlookup.SourceStatus{Source: source, State: ctlookup.StateTooLarge}, true
	case errors.As(err, &se) && se.code == http.StatusTooManyRequests:
		return ctlookup.SourceStatus{Source: source, State: ctlookup.StateRateLimited, RetryAfterS: seconds(se.retryAfter)}, true
	case errors.As(err, &se) && se.code >= 400 && se.code < 500 && se.code != http.StatusRequestTimeout:
		return unavailable(source), true
	case errors.Is(err, errBadAnswer):
		return unavailable(source), true
	}
	return unavailable(source), false
}

func unavailable(source string) ctlookup.SourceStatus {
	return ctlookup.SourceStatus{Source: source, State: ctlookup.StateUnavailable}
}

func seconds(d time.Duration) int {
	s := int((d + time.Second - 1) / time.Second)
	return min(max(s, 0), ctlookup.MaxRetryAfter)
}

// get waits for the source's turn, performs one GET and hands the body of a
// 200 answer to parse as a reader capped at MaxBodyBytes: the body is never
// held whole, parse reads what it needs. A body over the cap is errTooLarge.
func (c *Client) get(ctx context.Context, p *pacer, source, rawURL string, hdr http.Header, parse func(io.Reader) error) error {
	if wait, ok := p.reserve(maxPaceWait); !ok {
		return &rateLimited{wait: wait}
	} else if wait > 0 {
		if err := c.cfg.sleep(ctx, wait); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.cfg.UserAgent)
	resp, err := c.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		ra := min(parseRetryAfter(resp.Header.Get("Retry-After")), maxCoolDown)
		if resp.StatusCode == http.StatusTooManyRequests || ra > 0 {
			// Both bounds: a configured Interval of minutes must not turn
			// a 429 into a cool-down of hours.
			p.coolDown(min(max(ra, c.cfg.Interval*30), maxCoolDown))
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return &statusError{code: resp.StatusCode, retryAfter: ra}
	}
	if err := parse(&capReader{r: resp.Body, max: c.cfg.MaxBodyBytes}); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	return nil
}

// retryDelay is the wait before attempt n (n >= 1): the server's
// Retry-After when it sent a usable one, else base*2^(n-1) with jitter.
func retryDelay(attempt int, lastErr error) time.Duration {
	var se *statusError
	if errors.As(lastErr, &se) && se.retryAfter > 0 {
		return min(se.retryAfter, maxRetryAfter)
	}
	d := min(retryBase<<(attempt-1), retryCap)
	return d/2 + jitter(d/2)
}

func jitter(maxD time.Duration) time.Duration {
	if maxD <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(maxD)+1))
	if err != nil {
		return maxD
	}
	return time.Duration(n.Int64())
}

// parseRetryAfter reads Retry-After in seconds or as an HTTP date.
func parseRetryAfter(h string) time.Duration {
	h = strings.TrimSpace(h)
	if h == "" {
		return 0
	}
	if n, err := strconv.Atoi(h); err == nil {
		if n <= 0 {
			return 0
		}
		return min(time.Duration(n)*time.Second, time.Duration(ctlookup.MaxRetryAfter)*time.Second)
	}
	if t, err := http.ParseTime(h); err == nil {
		if d := time.Until(t); d > 0 {
			return min(d, time.Duration(ctlookup.MaxRetryAfter)*time.Second)
		}
	}
	return 0
}

// parseTime reads the time forms crt.sh and Cert Spotter use.
func parseTime(s string) time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func clipField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0) || r == 0x2028 || r == 0x2029 ||
			(r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) {
			return -1
		}
		return r
	}, s)
	if len(s) > ctlookup.MaxFieldLength {
		s = strings.ToValidUTF8(s[:ctlookup.MaxFieldLength], "")
	}
	return s
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// pacer spaces the requests to one source: one per interval, and none
// until a cool-down ends.
type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	now      func() time.Time
	next     time.Time
}

// reserve takes the next slot and returns how long to wait for it; ok is
// false (and nothing is taken) when the wait would exceed maxWait.
func (p *pacer) reserve(maxWait time.Duration) (time.Duration, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	at := now
	if p.next.After(now) {
		at = p.next
	}
	wait := at.Sub(now)
	if wait > maxWait {
		return wait, false
	}
	p.next = at.Add(p.interval)
	return wait, true
}

// coolDown keeps the source idle for d from now.
func (p *pacer) coolDown(d time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.now().Add(d); t.After(p.next) {
		p.next = t
	}
}

// cache keeps answers by key until they expire, bounded by encoded size
// (the oldest go first).
type cache struct {
	mu    sync.Mutex
	max   int64
	size  int64
	order []string
	items map[string]cacheItem
}

type cacheItem struct {
	out     ctlookup.Output
	expires time.Time
	size    int64
}

func newCache(maxBytes int64) *cache {
	return &cache{max: maxBytes, items: map[string]cacheItem{}}
}

func (c *cache) get(key string, now time.Time) (ctlookup.Output, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.items[key]
	if !ok || !now.Before(it.expires) {
		return ctlookup.Output{}, false
	}
	return it.out, true
}

func (c *cache) put(key string, out ctlookup.Output, expires time.Time) {
	b, err := json.Marshal(out)
	if err != nil || int64(len(b)) > c.max {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if old, ok := c.items[key]; ok {
		c.size -= old.size
		c.drop(key)
	}
	for c.size+int64(len(b)) > c.max && len(c.order) > 0 {
		k := c.order[0]
		c.order = c.order[1:]
		c.size -= c.items[k].size
		delete(c.items, k)
	}
	c.items[key] = cacheItem{out: out, expires: expires, size: int64(len(b))}
	c.order = append(c.order, key)
	c.size += int64(len(b))
}

func (c *cache) drop(key string) {
	delete(c.items, key)
	for i, k := range c.order {
		if k == key {
			c.order = append(c.order[:i], c.order[i+1:]...)
			return
		}
	}
}
