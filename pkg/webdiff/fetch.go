package webdiff

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openctemio/contract/edgeprotect"
)

// errHostile marks an answer that tried to exhaust the prober: a body whose
// decoding expands more than MaxRatio times, headers over MaxHeaderBytes, a
// body slower than the minimum transfer rate. The origin stops
// (GapHostileResponse).
var errHostile = errors.New("hostile response")

// errProtocol marks an answer that is not HTTP/1.x (GapProtocol).
var errProtocol = errors.New("not an HTTP/1.x answer")

// response is one fetched answer.
type response struct {
	sig  Sig
	edge edgeprotect.Verdict
	// retryAfter is the answer's Retry-After header value.
	retryAfter string
	// refused is set when the answer is the sensor's own refusal (the
	// forwarder's 403 marked X-Openctem-Egress: refused).
	refused string
}

// countReader counts the bytes consumed through it. It is a byte reader,
// so a decompressor reads from it directly (no read-ahead buffer of its
// own) and n is what was decoded so far, not what was buffered.
type countReader struct {
	r *bufio.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil {
		c.n++
	}
	return b, err
}

// rateReader fails a body that, once MinRateAfter has passed since its
// first byte was awaited, arrives slower than MinRate bytes per second.
type rateReader struct {
	r       io.Reader
	start   time.Time
	n       int64
	after   time.Duration
	minRate float64
	now     func() time.Time
}

func (r *rateReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	if el := r.now().Sub(r.start); el > r.after && float64(r.n)/el.Seconds() < r.minRate {
		return n, fmt.Errorf("%w: body slower than %.0f bytes/s", errHostile, r.minRate)
	}
	return n, err
}

// fetch sends one GET for u (an escaped path under the origin) and reads its
// answer within the bounds: the whole exchange within o.Deadline, headers
// within MaxHeaderBytes, at most MaxBody decoded body bytes, a gzip body
// decoded with the expansion ratio bounded, the body at the minimum rate.
// A redirect is never followed. tokens are the probed names the signature
// removes.
func (p *Prober) fetch(ctx context.Context, path string, tokens []string) (*response, error) {
	u, err := p.origin.Parse(path)
	if err != nil || u.Host != p.origin.Host || u.Scheme != p.origin.Scheme {
		return nil, fmt.Errorf("webdiff: %q is not a path of the origin", clip(path, 128))
	}
	if err := p.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.o.Deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	// The prober asks for gzip itself so that it decodes the body and can
	// bound the expansion (the transport would decode it unbounded).
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "*/*")
	p.requests++
	p.sinceCalibration++
	resp, err := p.client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), "response headers exceeded") {
			return nil, fmt.Errorf("%w: headers over %d bytes", errHostile, p.o.MaxHeaderBytes)
		}
		if strings.Contains(err.Error(), "malformed HTTP") || strings.Contains(err.Error(), "HTTP/2") {
			return nil, fmt.Errorf("%w: %v", errProtocol, err)
		}
		return nil, err
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 1 {
		return nil, errProtocol
	}
	if headerBytes(resp.Header) > p.o.MaxHeaderBytes {
		return nil, fmt.Errorf("%w: headers over %d bytes", errHostile, p.o.MaxHeaderBytes)
	}
	out := &response{retryAfter: resp.Header.Get("Retry-After")}
	if resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-Openctem-Egress") == "refused" {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		out.refused = string(b)
		out.sig = Sig{Status: resp.StatusCode}
		return out, nil
	}
	rr := &rateReader{r: resp.Body, start: p.now(), after: p.o.MinRateAfter, minRate: float64(p.o.MinRate), now: p.now}
	raw := &countReader{r: bufio.NewReader(rr)}
	var body io.Reader = raw
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Content-Encoding")), "gzip") {
		zr, err := gzip.NewReader(raw)
		if err != nil {
			body = strings.NewReader("") // an undecodable body: nothing to compare
		} else {
			defer zr.Close()
			body = &ratioReader{r: zr, raw: raw, max: p.o.MaxRatio}
		}
	}
	buf, err := io.ReadAll(io.LimitReader(body, int64(p.o.MaxBody)+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		if errors.Is(err, errHostile) {
			return nil, err
		}
		if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, fmt.Errorf("%w: no complete answer within %s", errHostile, p.o.Deadline)
		}
		return nil, err
	}
	truncated := len(buf) > p.o.MaxBody
	if truncated {
		buf = buf[:p.o.MaxBody]
	}
	out.sig = makeSig(resp, u, buf, truncated, tokens)
	out.edge = edgeprotect.Classify(resp.StatusCode, resp.Header, "", buf)
	return out, nil
}

// ratioReader fails a decoded stream that expands more than max times its
// encoded size (past the first 64 KiB, where small bodies may expand a lot).
type ratioReader struct {
	r   io.Reader
	raw *countReader
	n   int64
	max int
}

func (r *ratioReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	if r.n > 64<<10 && r.raw.n > 0 && r.n/r.raw.n > int64(r.max) {
		return n, fmt.Errorf("%w: body expands more than %d:1", errHostile, r.max)
	}
	return n, err
}

// headerBytes is the size of a header block as sent.
func headerBytes(h http.Header) int {
	n := 0
	for k, vs := range h {
		for _, v := range vs {
			n += len(k) + len(v) + 4
		}
	}
	return n
}
