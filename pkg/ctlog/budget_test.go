package ctlog

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/openctemio/contract/ctlookup"
)

// stall answers 200 at once and then sends nothing more until the client
// gives up: a crt.sh that is slow past any budget.
func stall(w http.ResponseWriter, r *http.Request, _ int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("["))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-r.Context().Done()
}

func TestSplitBudget(t *testing.T) {
	for _, tc := range []struct{ remaining, min, want time.Duration }{
		{100 * time.Second, 25 * time.Second, 70 * time.Second}, // 30 % = 30 s > 25 s
		{60 * time.Second, 25 * time.Second, 35 * time.Second},  // 25 s floor
		{40 * time.Second, 25 * time.Second, 20 * time.Second},  // never more than half
		{10 * time.Second, 25 * time.Second, 5 * time.Second},
		{0, 25 * time.Second, 0},
	} {
		if got := splitBudget(tc.remaining, tc.min); got != tc.want {
			t.Errorf("splitBudget(%s, %s) = %s, want %s", tc.remaining, tc.min, got, tc.want)
		}
	}
}

// A slow crt.sh must not use the whole budget of the lookup: Cert Spotter
// is asked with what is left, and the answer lists both source states
// instead of the lookup failing with the context's error.
func TestSlowCRTSHLeavesTheFallbackItsShare(t *testing.T) {
	cs := func(w http.ResponseWriter, r *http.Request, _ int) {
		if r.URL.Query().Get("after") != "" {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"7","dns_names":["www.example.com"],"issuer":{"name":"Example CA"}}]`))
	}
	// The job budget, scaled: crt.sh stalls for its 2 s, Cert Spotter keeps
	// 2 s, wide enough for a loaded runner. The states prove the share was
	// left (with none, the lookup fails with the context's error).
	h := newHarness(t, stall, cs, func(c *Config) { c.fallbackMin = 2 * time.Second })
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	out, err := h.c.Lookup(ctx, "tenant-a", ctlookup.Input{Domain: "example.com"})
	if err != nil {
		t.Fatalf("a slow crt.sh failed the lookup: %v", err)
	}
	want := []ctlookup.SourceStatus{{Source: ctlookup.SourceCRTSH, State: ctlookup.StateUnavailable}, {Source: ctlookup.SourceCertSpotter, State: ctlookup.StateOK}}
	if !slices.Equal(out.SourceStatus, want) {
		t.Fatalf("status %+v", out.SourceStatus)
	}
	if h.cs.count() != 2 || !slices.Equal(names(out), []string{"www.example.com"}) {
		t.Fatalf("Cert Spotter asked %d times, names %v", h.cs.count(), names(out))
	}
}

// With the fallback off, crt.sh keeps the whole budget.
func TestSlowCRTSHWithoutFallbackKeepsTheBudget(t *testing.T) {
	h := newHarness(t, stall, status(500, ""), func(c *Config) { c.CertSpotterOff = true; c.fallbackMin = 600 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	if _, err := h.c.Lookup(ctx, "tenant-a", ctlookup.Input{Domain: "example.com"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup past its own deadline: %v", err)
	}
}

// When the job's own context is done, that is the error (the caller reports
// a timeout); the answer is only for a live context.
func TestLookupErrorsWhenTheParentContextIsDone(t *testing.T) {
	h := newHarness(t, stall, stall, func(c *Config) { c.fallbackMin = 100 * time.Millisecond })
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := h.c.Lookup(ctx, "tenant-a", ctlookup.Input{Domain: "example.com"}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("both sources stalled past the budget: %v", err)
	}
}

// Cert Spotter still answering after its page limit is a cut list:
// too_large, none of it used, never ok. The too_large is definite, so it is
// remembered: the next lookup asks crt.sh again, not Cert Spotter.
func TestCertSpotterPageLimitIsNotOK(t *testing.T) {
	pages := 0
	cs := func(w http.ResponseWriter, _ *http.Request, n int) {
		pages = n
		_, _ = w.Write([]byte(`[{"id":"` + strconv.Itoa(n) + `","dns_names":["h` + strconv.Itoa(n) + `.example.com"]}]`))
	}
	h := newHarness(t, status(400, ""), cs, nil)
	out := h.lookup(t, "tenant-a", "example.com")
	if pages != certSpotterMaxPages+1 {
		t.Fatalf("%d pages asked, want %d", pages, certSpotterMaxPages+1)
	}
	if len(out.SourceStatus) != 2 || out.SourceStatus[1].State != ctlookup.StateTooLarge || len(out.Records) != 0 {
		t.Fatalf("out %+v", out)
	}
	again := h.lookup(t, "tenant-a", "example.com")
	if h.cs.count() != certSpotterMaxPages+1 || h.crt.count() != 2 {
		t.Fatalf("%d crt.sh, %d Cert Spotter requests", h.crt.count(), h.cs.count())
	}
	if !slices.Equal(again.SourceStatus, out.SourceStatus) {
		t.Fatalf("remembered %+v, first %+v", again.SourceStatus, out.SourceStatus)
	}
}

// When crt.sh failed in a way that may pass, the lookup is not cached as a
// whole, but Cert Spotter's too_large is remembered: crt.sh is asked again,
// Cert Spotter is not.
func TestCertSpotterTooLargeIsRememberedWhileCRTSHIsRetried(t *testing.T) {
	cs := func(w http.ResponseWriter, _ *http.Request, n int) {
		_, _ = w.Write([]byte(`[{"id":"` + strconv.Itoa(n) + `","dns_names":["h` + strconv.Itoa(n) + `.example.com"]}]`))
	}
	h := newHarness(t, status(503, ""), cs, nil)
	h.lookup(t, "tenant-a", "example.com")
	out := h.lookup(t, "tenant-a", "example.com")
	if h.crt.count() != 2*crtshAttempts || h.cs.count() != certSpotterMaxPages+1 {
		t.Fatalf("%d crt.sh, %d Cert Spotter requests", h.crt.count(), h.cs.count())
	}
	if len(out.SourceStatus) != 2 || out.SourceStatus[1].State != ctlookup.StateTooLarge {
		t.Fatalf("status %+v", out.SourceStatus)
	}
	// Expired with the answers' TTL.
	h.clock.t = h.clock.t.Add(DefaultCacheTTL + time.Minute)
	h.lookup(t, "tenant-a", "example.com")
	if h.cs.count() != 2*(certSpotterMaxPages+1) {
		t.Fatalf("too_large kept past the TTL: %d Cert Spotter requests", h.cs.count())
	}
	// Per tenant.
	h.lookup(t, "tenant-b", "example.com")
	if h.cs.count() != 3*(certSpotterMaxPages+1) {
		t.Fatalf("tenant-b got tenant-a's too_large: %d Cert Spotter requests", h.cs.count())
	}
}

// A list whose last page is the page limit's (lists of 901 to 1000 entries
// at 100 a page) is complete when the page after it is empty: ok, not
// too_large.
func TestCertSpotterListEndingOnTheLastPageIsOK(t *testing.T) {
	cs := func(w http.ResponseWriter, _ *http.Request, n int) {
		if n > certSpotterMaxPages {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"` + strconv.Itoa(n) + `","dns_names":["h` + strconv.Itoa(n) + `.example.com"]}]`))
	}
	h := newHarness(t, status(400, ""), cs, nil)
	out := h.lookup(t, "tenant-a", "example.com")
	if out.SourceStatus[1].State != ctlookup.StateOK || len(out.Records) != certSpotterMaxPages {
		t.Fatalf("status %+v, %d records", out.SourceStatus, len(out.Records))
	}
}

// A configured Interval scales the cool-down after a 429 with no
// Retry-After (30 intervals), but never past the cap.
func TestIntervalCoolDownIsCapped(t *testing.T) {
	h := newHarness(t, status(429, ""), status(400, ""), func(c *Config) { c.Interval = time.Hour })
	h.lookup(t, "tenant-a", "example.com")
	// The pace of one request an hour still holds; the cool-down does not
	// add 30 hours to it.
	h.clock.t = h.clock.t.Add(time.Hour + maxCoolDown)
	h.lookup(t, "tenant-b", "example.org")
	if h.crt.count() != 2 {
		t.Fatalf("crt.sh still cooling after the cap: %d requests", h.crt.count())
	}
}

// A list that ends on an empty page one before the limit is complete.
func TestCertSpotterShortListIsOK(t *testing.T) {
	cs := func(w http.ResponseWriter, _ *http.Request, n int) {
		if n >= certSpotterMaxPages {
			_, _ = w.Write([]byte("[]"))
			return
		}
		_, _ = w.Write([]byte(`[{"id":"` + strconv.Itoa(n) + `","dns_names":["h` + strconv.Itoa(n) + `.example.com"]}]`))
	}
	h := newHarness(t, status(400, ""), cs, nil)
	out := h.lookup(t, "tenant-a", "example.com")
	if out.SourceStatus[1].State != ctlookup.StateOK || len(out.Records) != certSpotterMaxPages-1 {
		t.Fatalf("out %+v", out.SourceStatus)
	}
}

// One Retry-After of a day cools a source down for 15 minutes, no longer:
// the cool-down is shared by every organization the sensor serves.
func TestRetryAfterCoolDownIsCapped(t *testing.T) {
	h := newHarness(t, status(429, "86400"), status(429, "86400"), nil)
	out := h.lookup(t, "tenant-a", "example.com")
	for _, s := range out.SourceStatus {
		if s.State != ctlookup.StateRateLimited || s.RetryAfterS != int(maxCoolDown/time.Second) {
			t.Fatalf("status %+v: want rate_limited asking for %s", out.SourceStatus, maxCoolDown)
		}
	}
	// Still cooling after 13 minutes (a wait of up to maxPaceWait for the
	// turn is allowed): nobody asks, for any organization.
	h.clock.t = h.clock.t.Add(13 * time.Minute)
	out = h.lookup(t, "tenant-b", "example.org")
	if h.crt.count() != 1 || h.cs.count() != 1 || out.SourceStatus[0].State != ctlookup.StateRateLimited {
		t.Fatalf("cool-down not kept: %d, %d requests, %+v", h.crt.count(), h.cs.count(), out.SourceStatus)
	}
	// Over after 16.
	h.clock.t = h.clock.t.Add(3 * time.Minute)
	h.lookup(t, "tenant-c", "example.net")
	if h.crt.count() != 2 {
		t.Fatalf("crt.sh still cooling after the cap: %d requests", h.crt.count())
	}
}
