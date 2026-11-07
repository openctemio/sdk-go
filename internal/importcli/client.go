package importcli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

// maxResponseBytes bounds what is read of an answer.
const maxResponseBytes = 4 << 20

// importPath is the upload route (RFC-122 receipts).
const importPath = "/api/v1/findings/imports"

// upload is one CTIS report to send.
type upload struct {
	name string
	body []byte
}

// client talks to one console with one API key.
type client struct {
	base        *url.URL
	key         string
	http        *http.Client
	minSeverity string
	// poll is the pause between two result reads when the server answers
	// at once (the server's own wait is at most 10 s).
	poll time.Duration
}

// newClient checks the URL and the key. The key is sent only over HTTPS, or
// plain HTTP to a loopback address (a console on this machine).
func newClient(base, key, caFile string) (*client, error) {
	key = strings.TrimSpace(key)
	if base == "" {
		return nil, errors.New("set " + EnvURL + " (or --url) to the console URL, or use --dry-run or --out")
	}
	if key == "" {
		return nil, errors.New("set " + EnvAPIKey + " to an API key with Update Findings, Manage Assets and Import Assets, or use --dry-run or --out")
	}
	if strings.ContainsAny(key, "\r\n") {
		return nil, errors.New(EnvAPIKey + " holds a line break")
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%q is not a console URL (https://console.example.com)", clean(base, 120))
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return nil, errors.New("the API key is sent only over HTTPS (plain HTTP only to localhost)")
		}
	default:
		return nil, fmt.Errorf("%q is not an http(s) URL", clean(base, 120))
	}
	tr, err := transport(caFile)
	if err != nil {
		return nil, err
	}
	return &client{
		base: u, key: key, poll: 2 * time.Second,
		http: &http.Client{
			Transport: tr,
			Timeout:   5 * time.Minute,
			// A redirect would carry the upload, and possibly the key,
			// somewhere else: it is an error.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

// transport is the default one (HTTPS_PROXY, HTTP_PROXY and NO_PROXY are
// honored) with TLS 1.2 at least. A CA file adds its certificates to the
// system roots; it never replaces them, and verification is never skipped.
// On Windows and macOS the system roots are the platform's own verifier
// (the Windows certificate store): Go tries it first and falls back to the
// added certificates only when it refuses the chain.
func transport(caFile string) (*http.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	caFile = strings.TrimSpace(caFile)
	if caFile == "" {
		return tr, nil
	}
	pem, err := readFileLimited(caFile, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("CA file %s: %v", clean(caFile, 200), err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s holds no PEM certificate", clean(caFile, 200))
	}
	tr.TLSClientConfig.RootCAs = pool
	return tr, nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// importResponse is the answer of the upload and result routes.
type importResponse struct {
	ReceiptID string         `json:"receipt_id,omitempty"`
	Status    string         `json:"status,omitempty"`
	ErrorCode string         `json:"error_code,omitempty"`
	Files     []importFile   `json:"files"`
	Receipt   *importReceipt `json:"receipt,omitempty"`
	// Set by the client: an answer that is not a result (an HTTP error).
	HTTPStatus int    `json:"-"`
	Message    string `json:"-"`
}

type importFile struct {
	Name       string `json:"name"`
	Format     string `json:"format,omitempty"`
	Candidates int    `json:"candidates,omitempty"`
	Error      *struct {
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
	Issues []struct {
		Message string `json:"message"`
	} `json:"issues,omitempty"`
}

type importReceipt struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Counts struct {
		Created     int `json:"created"`
		Updated     int `json:"updated"`
		Reactivated int `json:"reactivated"`
		Closed      int `json:"closed"`
		Skipped     int `json:"skipped"`
		Failed      int `json:"failed"`
		Suppressed  int `json:"suppressed"`
	} `json:"counts"`
	Received int `json:"received"`
	Assets   struct {
		Created int `json:"created"`
		Updated int `json:"updated"`
	} `json:"assets"`
	Errors []struct {
		Index int    `json:"index"`
		Code  string `json:"code"`
	} `json:"errors"`
	Dispositions map[string]int `json:"dispositions,omitempty"`
}

// done reports whether the upload reached a final state.
func (r *importResponse) done() bool {
	switch r.Status {
	case "applied", "failed", "completed":
		return true
	}
	return r.HTTPStatus >= 300
}

func (r *importResponse) exitCode() int {
	switch {
	case r.HTTPStatus >= 300 || r.Status == "failed" || r.ErrorCode != "":
		return ExitFail
	case r.Status == "applied" || r.Status == "completed":
		for _, f := range r.Files {
			if f.Error != nil {
				return ExitFail
			}
		}
		return ExitOK
	}
	return ExitPending
}

// upload sends the reports in one request. The Idempotency-Key is the
// digest of the reports, so sending the same bytes again (an offline file
// uploaded twice) returns the same receipt instead of a second import.
func (c *client) upload(ctx context.Context, files []upload) (*importResponse, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	h := sha256.New()
	for _, f := range files {
		hdr := textproto.MIMEHeader{}
		hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, partName(f.name)))
		hdr.Set("Content-Type", "application/json")
		pw, err := mw.CreatePart(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := pw.Write(f.body); err != nil {
			return nil, err
		}
		_, _ = h.Write(f.body)
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	q := url.Values{"format": {"ctis"}}
	if c.minSeverity != "" {
		q.Set("min_severity", c.minSeverity)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(importPath+"/", q), &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Idempotency-Key", "openctem-import-"+hex.EncodeToString(h.Sum(nil))[:48])
	return c.do(req)
}

// follow reads the upload's result until it is final or wait has passed.
func (c *client) follow(ctx context.Context, r *importResponse, wait time.Duration) *importResponse {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		w := time.Until(deadline)
		if w > 10*time.Second {
			w = 10 * time.Second
		}
		q := url.Values{"wait": {fmt.Sprintf("%d", int(w.Seconds()))}}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(importPath+"/"+url.PathEscape(r.ReceiptID)+"/result", q), nil)
		if err != nil {
			return r
		}
		next, err := c.do(req)
		if err != nil || next.HTTPStatus >= 300 {
			return r
		}
		if next.ReceiptID == "" {
			next.ReceiptID = r.ReceiptID
		}
		r = next
		if r.done() {
			return r
		}
		select {
		case <-ctx.Done():
			return r
		case <-time.After(c.poll):
		}
	}
	return r
}

func (c *client) endpoint(path string, q url.Values) string {
	u := *c.base
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *client) do(req *http.Request) (*importResponse, error) {
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openctem-import/"+useragent.SDKVersion())
	resp, err := c.http.Do(req)
	if err != nil {
		// The error names the URL, never the key (it is a header).
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, err
	}
	out := &importResponse{}
	if resp.StatusCode >= 300 {
		out.HTTPStatus = resp.StatusCode
		var e struct {
			Message string `json:"message"`
			Error   string `json:"error"`
			Code    string `json:"code"`
		}
		_ = json.Unmarshal(data, &e)
		out.Message = firstNonEmpty(e.Message, e.Error, http.StatusText(resp.StatusCode))
		out.ErrorCode = e.Code
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			out.Message = "the console answered with a redirect (" + resp.Status + "): check " + EnvURL
		}
		return out, nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return nil, fmt.Errorf("the console's answer is not an import result (HTTP %d)", resp.StatusCode)
	}
	return out, nil
}

func partName(n string) string {
	n = strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, n)
	if !strings.HasSuffix(n, ".json") {
		n += ".ctis.json"
	}
	return n
}

func printReceipt(w io.Writer, r *importResponse) {
	if r.HTTPStatus >= 300 {
		msg := clean(r.Message, 300)
		if r.HTTPStatus == http.StatusBadRequest && strings.Contains(msg, "unknown format") {
			msg += " (this console does not accept CTIS uploads yet: upgrade it, or upload the tool's own file on the Import results page)"
		}
		_, _ = fmt.Fprintf(w, "refused: HTTP %d: %s\n", r.HTTPStatus, msg)
		return
	}
	_, _ = fmt.Fprintf(w, "receipt %s: %s\n", clean(r.ReceiptID, 64), clean(firstNonEmpty(r.Status, "queued"), 32))
	if r.ErrorCode != "" {
		_, _ = fmt.Fprintf(w, "  error   %s\n", clean(r.ErrorCode, 64))
	}
	held := 0
	for _, f := range r.Files {
		held += f.Candidates
		if f.Error != nil {
			_, _ = fmt.Fprintf(w, "  %s refused: %s\n", clean(f.Name, 120), clean(f.Error.Message, 300))
		}
	}
	if rc := r.Receipt; rc != nil {
		k := rc.Counts
		_, _ = fmt.Fprintf(w, "  findings  received %d  created %d  updated %d  reactivated %d  skipped %d  failed %d  suppressed %d\n",
			rc.Received, k.Created, k.Updated, k.Reactivated, k.Skipped, k.Failed, k.Suppressed)
		_, _ = fmt.Fprintf(w, "  assets    created %d  updated %d\n", rc.Assets.Created, rc.Assets.Updated)
		if len(rc.Dispositions) > 0 {
			keys := make([]string, 0, len(rc.Dispositions))
			for k := range rc.Dispositions {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var parts []string
			for _, k := range keys {
				parts = append(parts, fmt.Sprintf("%s %d", clean(k, 40), rc.Dispositions[k]))
			}
			_, _ = fmt.Fprintf(w, "  refused   %s\n", strings.Join(parts, "  "))
		}
		for i, e := range rc.Errors {
			if i == 10 {
				break
			}
			_, _ = fmt.Fprintf(w, "  error     report %d: %s\n", e.Index, clean(e.Code, 64))
		}
	}
	if held > 0 {
		_, _ = fmt.Fprintf(w, "  held      %d hosts outside the organization's scope (candidates: recorded, never scanned)\n", held)
	}
	if !r.done() {
		_, _ = fmt.Fprintf(w, "  still %s: the platform applies it shortly (openctem import exits 3)\n", clean(firstNonEmpty(r.Status, "queued"), 32))
	}
}

func utf8Valid(s string) bool { return utf8.ValidString(s) }
