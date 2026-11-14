package adapt

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestThrottleTallyObserve(t *testing.T) {
	for _, tc := range []struct {
		name       string
		target     string
		status     int
		retryAfter time.Duration
		want       bool
	}{
		{"429", "a.example.com", 429, 0, true},
		{"503", "a.example.com", 503, 0, true},
		{"200 with Retry-After", "a.example.com", 200, 5 * time.Second, true},
		{"200", "a.example.com", 200, 0, false},
		{"403 is a block, not a rate limit", "a.example.com", 403, 0, false},
		{"500", "a.example.com", 500, 0, false},
		{"no target", "", 429, 0, false},
	} {
		var tt ThrottleTally
		if got := tt.Observe(tc.target, tc.status, tc.retryAfter); got != tc.want {
			t.Errorf("%s: Observe = %v, want %v", tc.name, got, tc.want)
		}
		if got := tt.Throttled(tc.target); got != tc.want {
			t.Errorf("%s: Throttled = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Each throttled target is one gap with its counts; the longest Retry-After
// is kept (capped), and a clean target is no gap.
func TestThrottleTallyGaps(t *testing.T) {
	var tt ThrottleTally
	tt.Observe("a.example.com", 429, 30*time.Second)
	tt.Observe("a.example.com", 429, 0)
	tt.Observe("a.example.com", 503, 0)
	tt.Observe("b.example.com", 503, 0)
	tt.Observe("c.example.com", 200, 0)
	tt.Observe("d.example.com", 429, time.Hour)

	gaps, total := tt.Gaps()
	if total != 3 || len(gaps) != 3 {
		t.Fatalf("gaps %+v total %d, want 3", gaps, total)
	}
	want := []Gap{
		{Host: "a.example.com", Reason: GapThrottled, Detail: "429=2 503=1 retry_after=30s"},
		{Host: "b.example.com", Reason: GapThrottled, Detail: "503=1"},
		{Host: "d.example.com", Reason: GapThrottled, Detail: "429=1 retry_after=5m0s"},
	}
	for i := range want {
		if gaps[i] != want[i] {
			t.Errorf("gap %d = %+v, want %+v", i, gaps[i], want[i])
		}
	}
	if got := tt.RetryAfter(); got != TargetRate.RetryAfterMax {
		t.Errorf("RetryAfter = %s, want the cap %s", got, TargetRate.RetryAfterMax)
	}
	n, tooMany, unavailable, ra := tt.Summary()
	if n != 3 || tooMany != 3 || unavailable != 2 || ra != TargetRate.RetryAfterMax {
		t.Errorf("Summary = %d %d %d %s", n, tooMany, unavailable, ra)
	}
	if tt.Count() != 3 {
		t.Errorf("Count = %d", tt.Count())
	}
}

func TestThrottleTallyEmpty(t *testing.T) {
	var tt ThrottleTally
	if g, n := tt.Gaps(); g != nil || n != 0 {
		t.Fatalf("empty tally gaps %+v %d", g, n)
	}
	if tt.RetryAfter() != 0 || tt.Throttled("x") {
		t.Fatal("empty tally reports push-back")
	}
}

// The listed gaps are bounded; the total still counts every target.
func TestThrottleTallyBounds(t *testing.T) {
	var tt ThrottleTally
	n := TargetRate.MaxGaps + 7
	for i := range n {
		tt.Observe(fmt.Sprintf("h%d.example.com", i), 429, 0)
	}
	gaps, total := tt.Gaps()
	if len(gaps) != TargetRate.MaxGaps || total != n {
		t.Fatalf("len %d total %d, want %d and %d", len(gaps), total, TargetRate.MaxGaps, n)
	}
}

func TestThrottleTallyConcurrent(t *testing.T) {
	var tt ThrottleTally
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 50 {
				tt.Observe(fmt.Sprintf("h%d.example.com", (i+j)%5), 429, 0)
			}
		}()
	}
	wg.Wait()
	_, tooMany, _, _ := tt.Summary()
	if tooMany != 400 || tt.Count() != 5 {
		t.Fatalf("429s %d targets %d, want 400 and 5", tooMany, tt.Count())
	}
}
