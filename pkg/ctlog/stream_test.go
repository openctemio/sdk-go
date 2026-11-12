package ctlog

import (
	"context"
	"errors"
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

// giantRow streams prefix + n copies of unit + suffix without holding them:
// one row of any size costs the test nothing.
type giantRow struct {
	prefix, unit, suffix string
	n, sent              int
	stage                int
	pending, block       string
}

func (g *giantRow) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if g.pending == "" {
			switch {
			case g.stage == 0:
				g.pending, g.stage = g.prefix, 1
			case g.stage == 1 && g.sent < g.n:
				// Many units per refill keep the generator cheap.
				if g.block == "" {
					g.block = strings.Repeat(g.unit, 4096)
				}
				k := min(4096, g.n-g.sent)
				g.pending, g.sent = g.block[:k*len(g.unit)], g.sent+k
			case g.stage == 1:
				g.pending, g.stage = g.suffix, 2
			default:
				if n == 0 {
					return 0, io.EOF
				}
				return n, nil
			}
		}
		c := copy(p[n:], g.pending)
		g.pending = g.pending[c:]
		n += c
	}
	return n, nil
}

func streamGiant(g giantRow) func(http.ResponseWriter, *http.Request, int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		gg := g
		_, _ = io.Copy(w, &gg)
	}
}

// One crt.sh row of about 40 MiB of names (under the body cap) is refused
// at the row cap: too_large, and the lookup allocates a few MiB, not the row.
func TestCRTSHOneGiantRowIsTooLargeAndCheap(t *testing.T) {
	g := giantRow{prefix: `[{"id":1,"name_value":"`, unit: `a.example.com\n`, suffix: `"}]`, n: 3_000_000}
	h := newHarness(t, streamGiant(g), status(500, ""), func(c *Config) { c.CertSpotterOff = true })
	var out ctlookup.Output
	alloc := heapChurn(func() { out = h.lookup(t, "tenant-a", "example.com") })
	if len(out.SourceStatus) != 1 || out.SourceStatus[0].State != ctlookup.StateTooLarge || len(out.Records) != 0 {
		t.Fatalf("out %+v", out)
	}
	if alloc > allocBound {
		t.Fatalf("one giant row cost %d MiB of allocations (bound %d MiB)", alloc>>20, allocBound>>20)
	}
}

// The same for one Cert Spotter issuance with millions of dns_names.
func TestCertSpotterOneGiantRowIsTooLargeAndCheap(t *testing.T) {
	g := giantRow{prefix: `[{"id":"1","dns_names":["a.example.com"`, unit: `,"a.example.com"`, suffix: `]}]`, n: 3_000_000}
	h := newHarness(t, status(503, ""), streamGiant(g), nil)
	var out ctlookup.Output
	alloc := heapChurn(func() { out = h.lookup(t, "tenant-a", "example.com") })
	if len(out.SourceStatus) != 2 || out.SourceStatus[1].State != ctlookup.StateTooLarge || len(out.Records) != 0 {
		t.Fatalf("out %+v", out)
	}
	if alloc > allocBound {
		t.Fatalf("one giant row cost %d MiB of allocations (bound %d MiB)", alloc>>20, allocBound>>20)
	}
}

// A row under the row cap with many names keeps the first
// MaxNamesPerRecord, and the rest never become strings or slice entries.
func TestRowNamesAreCutWhileRead(t *testing.T) {
	const many = 100_000 // about 1.5 MiB: under the row cap
	crt := giantRow{prefix: `[{"id":1,"name_value":"a.example.com`, unit: `\na.example.com`, suffix: `"}]`, n: many}
	recs, err := parseCRTSH(&crt)
	if err != nil || len(recs) != 1 || len(recs[0].DNSNames) != ctlookup.MaxNamesPerRecord {
		t.Fatalf("crt.sh: err %v, %d records", err, len(recs))
	}
	for _, n := range recs[0].DNSNames {
		if n != "a.example.com" {
			t.Fatalf("crt.sh: a cut name kept the rest of the row (%d bytes)", len(n))
		}
	}
	cs := giantRow{prefix: `[{"id":"1","dns_names":["a.example.com"`, unit: `,"a.example.com"`, suffix: `]}]`, n: many}
	var got []certSpotterIssuance
	if err := decodeArray(&cs, 10, func(it certSpotterIssuance) { got = append(got, it) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].DNSNames) != ctlookup.MaxNamesPerRecord {
		t.Fatalf("Cert Spotter: %d issuances", len(got))
	}
	// A row exactly at the cap is read; the cap is per row, not per answer.
	var rows []crtshEntry
	row := `{"id":1,"name_value":"` + strings.Repeat("a", maxRowBytes-len(`{"id":1,"name_value":""}`)) + `"}`
	body := "[" + row + "," + row + "]"
	if err := decodeArray(strings.NewReader(body), 10, func(e crtshEntry) { rows = append(rows, e) }); err != nil || len(rows) != 2 {
		t.Fatalf("two rows at the cap: %d rows, err %v", len(rows), err)
	}
	if err := decodeArray(strings.NewReader("["+row[:len(row)-2]+`aa"}`+"]"), 10, func(crtshEntry) {}); !errors.Is(err, errTooLarge) {
		t.Fatalf("a row one byte over the cap: %v", err)
	}
}
