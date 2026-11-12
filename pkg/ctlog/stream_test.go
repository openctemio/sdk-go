package ctlog

import (
	"context"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/openctemio/contract/ctlookup"
)

// rowsReader streams "[" + n copies of row (comma separated) + "]" without
// holding them: a hostile answer of many small rows costs the test nothing.
type rowsReader struct {
	row     string
	n, sent int
	stage   int // 0 "[", 1 rows, 2 "]", 3 done
	pending string
}

func (r *rowsReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pending == "" {
			switch r.stage {
			case 0:
				r.pending, r.stage = "[", 1
			case 1:
				if r.sent >= r.n {
					r.stage = 2
					continue
				}
				if r.sent > 0 {
					r.pending = "," + r.row
				} else {
					r.pending = r.row
				}
				r.sent++
			case 2:
				r.pending, r.stage = "]", 3
			default:
				if n == 0 {
					return 0, io.EOF
				}
				return n, nil
			}
		}
		c := copy(p[n:], r.pending)
		r.pending = r.pending[c:]
		n += c
	}
	return n, nil
}

func streamRows(row string, n int) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		_, _ = io.Copy(w, &rowsReader{row: row, n: n})
	}
}

// allocBound is what a refused hostile answer may allocate in all: far under
// what decoding it whole costs (hundreds of MiB), far over the work up to the
// record cap.
const allocBound = 64 << 20

const (
	// small rows: a million of them are about 40 MB, under the body cap, so
	// only the record cap stops them.
	tinyCRTRow = `{"id":1,"name_value":"a.example.com"}`
	tinyCSRow  = `{"id":"1","dns_names":["a.example.com"]}`
	crtRow     = `{"id":1,"issuer_name":"C=US, O=Example CA","common_name":"a.example.com","name_value":"a.example.com\nb.example.com","serial_number":"01","not_before":"2026-01-01T00:00:00","not_after":"2027-01-01T00:00:00"}`
	csRow      = `{"id":"1","dns_names":["a.example.com"],"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z","issuer":{"name":"Example CA"},"cert_sha256":"ab"}`
)

// heapChurn returns the bytes allocated by f (all goroutines: the fake
// source's server side counts too, and is small).
func heapChurn(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// A hostile crt.sh answer of a million small rows (under the body cap) is refused at the record cap
// without decoding the rest: the work is bounded by the cap, not the body.
func TestCRTSHHostileManyRowsIsTooLargeAndCheap(t *testing.T) {
	h := newHarness(t, streamRows(tinyCRTRow, 1_000_000), status(500, ""), func(c *Config) { c.CertSpotterOff = true })
	var out ctlookup.Output
	alloc := heapChurn(func() { out = h.lookup(t, "tenant-a", "example.com") })
	if len(out.Records) != 0 || len(out.SourceStatus) != 1 || out.SourceStatus[0].State != ctlookup.StateTooLarge {
		t.Fatalf("out %+v", out)
	}
	if h.crt.count() != 1 {
		t.Fatalf("a too large answer was retried: %d requests", h.crt.count())
	}
	if alloc > allocBound {
		t.Fatalf("a refused answer cost %d MiB of allocations (bound %d MiB)", alloc>>20, allocBound>>20)
	}
}

func TestCertSpotterHostileManyRowsIsTooLargeAndCheap(t *testing.T) {
	h := newHarness(t, status(503, ""), streamRows(tinyCSRow, 1_000_000), nil)
	var out ctlookup.Output
	alloc := heapChurn(func() { out = h.lookup(t, "tenant-a", "example.com") })
	if len(out.SourceStatus) != 2 || out.SourceStatus[1].State != ctlookup.StateTooLarge || len(out.Records) != 0 {
		t.Fatalf("out %+v", out)
	}
	if alloc > allocBound {
		t.Fatalf("a refused answer cost %d MiB of allocations (bound %d MiB)", alloc>>20, allocBound>>20)
	}
}

// Exactly the record cap is an answer; one more is too large.
func TestCRTSHRecordCapIsExact(t *testing.T) {
	h := newHarness(t, streamRows(crtRow, ctlookup.MaxRecords), status(500, ""), func(c *Config) { c.CertSpotterOff = true })
	// 20000 rows are over the contract's output size: capSize refuses the
	// encoded answer, but the source itself was read to the end and was ok.
	out := h.lookup(t, "tenant-a", "example.com")
	if len(out.SourceStatus) != 1 || (out.SourceStatus[0].State != ctlookup.StateOK && out.SourceStatus[0].State != ctlookup.StateTooLarge) {
		t.Fatalf("status %+v", out.SourceStatus)
	}
	recs, err := parseCRTSH(&rowsReader{row: crtRow, n: ctlookup.MaxRecords})
	if err != nil || len(recs) != ctlookup.MaxRecords {
		t.Fatalf("%d records, err %v", len(recs), err)
	}
	if _, err := parseCRTSH(&rowsReader{row: crtRow, n: ctlookup.MaxRecords + 1}); err == nil || !strings.Contains(err.Error(), errTooMany.Error()) {
		t.Fatalf("one over the cap: %v", err)
	}
}

// crt.sh answers "[]" for no certificates: an empty body is not an answer,
// and is not cached as "ok, nothing found".
func TestCRTSHEmptyBodyIsABadAnswerNotCached(t *testing.T) {
	for _, body := range []string{"", "  \n", "null", "{}", `"x"`} {
		h := newHarness(t, serve([]byte(body)), status(500, ""), nil)
		out := h.lookup(t, "tenant-a", "example.com")
		if out.SourceStatus[0].State != ctlookup.StateUnavailable {
			t.Fatalf("body %q: crt.sh state %+v", body, out.SourceStatus)
		}
		if h.crt.count() != 1 {
			t.Fatalf("body %q: a bad answer was retried: %d", body, h.crt.count())
		}
		h.lookup(t, "tenant-a", "example.com")
		if h.crt.count() != 2 {
			t.Fatalf("body %q: a bad answer was cached", body)
		}
	}
	h := newHarness(t, serve([]byte("[]")), status(500, ""), nil)
	out := h.lookup(t, "tenant-a", "example.com")
	if out.SourceStatus[0].State != ctlookup.StateOK || len(out.Records) != 0 {
		t.Fatalf("an empty list is an answer: %+v", out)
	}
}

// The size cap holds for the whole body, also past a complete list.
func TestBodyCapCoversTrailingBytes(t *testing.T) {
	body := "[]" + strings.Repeat(" ", 200)
	h := newHarness(t, serve([]byte(body)), status(500, ""), func(c *Config) { c.MaxBodyBytes = 100; c.CertSpotterOff = true })
	out := h.lookup(t, "tenant-a", "example.com")
	if out.SourceStatus[0].State != ctlookup.StateTooLarge {
		t.Fatalf("status %+v", out.SourceStatus)
	}
}

// A cut connection mid-body is a retryable failure, not a bad answer.
func TestCutBodyIsRetried(t *testing.T) {
	cut := func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Length", "1000")
		_, _ = w.Write([]byte(`[{"id":1,`))
	}
	h := newHarness(t, cut, status(500, ""), func(c *Config) { c.CertSpotterOff = true })
	out, err := h.c.Lookup(context.Background(), "tenant-a", ctlookup.Input{Domain: "example.com"})
	if err != nil || out.SourceStatus[0].State != ctlookup.StateUnavailable {
		t.Fatalf("out %+v err %v", out, err)
	}
	if h.crt.count() != crtshAttempts {
		t.Fatalf("a cut body was tried %d times, want %d", h.crt.count(), crtshAttempts)
	}
}
