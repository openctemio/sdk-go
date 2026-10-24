package egress

import (
	"errors"
	"io"
	"net/http"

	"github.com/openctemio/sdk-go/pkg/adapt"
	"github.com/openctemio/sdk-go/pkg/edgeprotect"
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
func (f *Forwarder) observeResponse(host string, resp *http.Response) {
	// Only the headers are visible here (the body streams to the tool); a
	// vendor's challenge or block that shows in its headers is a block from
	// the first answer, a bare 403 stays an ordinary answer.
	v := edgeprotect.Classify(resp.StatusCode, resp.Header, "", nil)
	f.hostRate.ReportResponse(normName(host), resp.StatusCode, resp.Header.Get("Retry-After"), v)
}

// observeErr feeds a network error toward host to the rate controller
// (errors that say nothing about the host are ignored).
func (f *Forwarder) observeErr(host string, err error) {
	if reason := adapt.FailureReason(err); reason != "" {
		f.hostRate.Report(normName(host), adapt.Event{Signal: adapt.Failed, Reason: reason})
	}
}
