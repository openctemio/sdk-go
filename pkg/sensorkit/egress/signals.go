package egress

import (
	"bufio"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/openctemio/contract/edgeprotect"
	"github.com/openctemio/sdk-go/pkg/adapt"
)

// errReader remembers the first read error other than EOF: the host
// resetting a connection, or timing out.
type errReader struct {
	r   io.Reader
	err error
}

func (e *errReader) Read(p []byte) (int, error) {
	n, err := e.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) && e.err == nil {
		e.err = err
	}
	return n, err
}

// observeResponse feeds an HTTP answer of host to the rate controller.
// body is the start of the answer's body that already arrived with its
// headers (bufferedBody; nil when none did): the body streams to the tool
// and is never waited for. A vendor's challenge, block or rate-limit page
// that shows in the headers or in that start is a block (or a push-back)
// from the first answer; a bare 403 stays an ordinary answer.
func (f *Forwarder) observeResponse(host string, resp *http.Response, body []byte) {
	v := edgeprotect.Classify(resp.StatusCode, resp.Header, "", body)
	f.hostRate.ReportResponse(normName(host), resp.StatusCode, resp.Header.Get("Retry-After"), v)
}

// bufferedBody is the start of resp's body that br already holds (at most
// edgeprotect.MaxBody bytes), without reading further: the forwarder never
// delays an answer to classify it. A compressed body is not read (its
// bytes say nothing until decoded).
func bufferedBody(br *bufio.Reader, resp *http.Response) []byte {
	if ce := resp.Header.Get("Content-Encoding"); ce != "" && !strings.EqualFold(ce, "identity") {
		return nil
	}
	n := min(br.Buffered(), edgeprotect.MaxBody)
	if resp.ContentLength >= 0 {
		n = min(n, int(min(resp.ContentLength, int64(edgeprotect.MaxBody))))
	}
	if n <= 0 {
		return nil
	}
	b, err := br.Peek(n)
	if err != nil {
		return nil
	}
	return b
}

// observeErr feeds a network error toward host to the rate controller
// (errors that say nothing about the host are ignored).
func (f *Forwarder) observeErr(host string, err error) {
	if reason := adapt.FailureReason(err); reason != "" {
		f.hostRate.Report(normName(host), adapt.Event{Signal: adapt.Failed, Reason: reason})
	}
}
