package identity

import (
	"bytes"
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"strings"
	"testing"
	"time"
)

func clockSkewReply(offset int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/sensor/clock-skew","title":"Clock skew","status":401,` +
			`"detail":"x","server_time":"2026-10-25T14:00:00Z","clock_offset_seconds":` + itoa(offset) + `,"retryable":false}`))
	}
}

func itoa(n int) string {
	neg := n < 0
	if neg {
		n = -n
	}
	b := []byte{}
	for {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
		if n == 0 {
			break
		}
	}
	if neg {
		b = append([]byte{'-'}, b...)
	}
	return string(b)
}

func statusReply(code int, header ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		http.Error(w, http.StatusText(code), code)
	}
}

// The platform's clock-skew problem becomes an error that names the offset,
// its direction and the fix.
func TestPairClockSkewProblemIsExplained(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){clockSkewReply(-15006)}
	_, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{}))
	var ce *ClockSkewError
	if !errors.As(err, &ce) || ce.Offset != -(4*time.Hour+10*time.Minute+6*time.Second) {
		t.Fatalf("want a clock skew of -4h10m6s, got %v", err)
	}
	for _, want := range []string{"behind", "4h10m6s", "NTP", "chronyc makestep"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message lacks %q: %s", want, err)
		}
	}
}

// A platform that answers only the generic 401 still gets the clock
// diagnosis when its Date header is far from this machine's clock.
func TestPairClockSkewFromTheDateHeader(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){func(w http.ResponseWriter) {
		w.Header().Set("Date", time.Now().Add(4*time.Hour).UTC().Format(http.TimeFormat))
		http.Error(w, "unauthenticated", http.StatusUnauthorized)
	}}
	_, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{}))
	var ce *ClockSkewError
	if !errors.As(err, &ce) || ce.Offset > -4*time.Hour+5*time.Second || ce.Offset < -4*time.Hour-5*time.Second {
		t.Fatalf("want a clock skew of about -4h, got %v", err)
	}
	// A generic 401 with a right Date is not a clock skew.
	f.startReplies = []func(http.ResponseWriter){statusReply(http.StatusUnauthorized)}
	if _, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{})); errors.As(err, &ce) || err == nil {
		t.Fatalf("generic 401 read as %v", err)
	}
}

// With RetryTransient, a clock skew, an unavailable platform and a generic
// 401 are retried in process with capped exponential backoff and a message
// each time, then pairing completes with the same key. Every transient delay
// is full jitter: in [base/2, base].
func TestPairRetriesTransientFailuresWithBackoff(t *testing.T) {
	for _, tc := range []struct {
		name string
		rnd  func(int64) int64
		frac func(base time.Duration) time.Duration // expected delay for a base
	}{
		{"max jitter", func(n int64) int64 { return n - 1 }, func(b time.Duration) time.Duration { return b }},
		{"min jitter", func(int64) int64 { return 0 }, func(b time.Duration) time.Duration { return b / 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			f.startReplies = []func(http.ResponseWriter){clockSkewReply(15000)}
			for range 7 {
				f.startReplies = append(f.startReplies, statusReply(http.StatusServiceUnavailable))
			}
			f.startReplies = append(f.startReplies, statusReply(http.StatusUnauthorized))
			var out bytes.Buffer
			o := opts(t, srv, &out)
			o.RetryTransient = true
			o.rnd = tc.rnd
			var sleeps []time.Duration
			o.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
			if _, err := Pair(context.Background(), o); err != nil {
				t.Fatalf("pairing after transient failures: %v", err)
			}
			bases := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
				160 * time.Second, 5 * time.Minute, 5 * time.Minute}
			if len(sleeps) < len(bases)+1 {
				t.Fatalf("sleeps %v", sleeps)
			}
			for i, b := range bases {
				if sleeps[i] != tc.frac(b) {
					t.Fatalf("delay %d = %v, want %v (all %v)", i, sleeps[i], tc.frac(b), sleeps)
				}
			}
			// The generic 401 is not transient: it waits at least 5 minutes.
			if sleeps[len(bases)] < 5*time.Minute {
				t.Fatalf("a generic 401 waited %v", sleeps[len(bases)])
			}
			if f.starts != 10 || !f.confirmed {
				t.Fatalf("starts=%d confirmed=%v", f.starts, f.confirmed)
			}
			if !strings.Contains(out.String(), "ahead of the platform") || !strings.Contains(out.String(), "Retrying in ") {
				t.Fatalf("output:\n%s", out.String())
			}
		})
	}
}

func TestFullJitterBounds(t *testing.T) {
	for _, base := range []time.Duration{5 * time.Second, 5 * time.Minute} {
		lo, hi := fullJitter(base, func(int64) int64 { return 0 }), fullJitter(base, func(n int64) int64 { return n - 1 })
		if lo != base/2 || hi != base {
			t.Fatalf("base %v: [%v, %v]", base, lo, hi)
		}
	}
	// With the real generator every delay stays in range.
	for range 500 {
		if d := fullJitter(10*time.Second, rand.Int64N); d < 5*time.Second || d > 10*time.Second {
			t.Fatalf("delay %v out of [5s, 10s]", d)
		}
	}
}

func problemReply(status int, slug, title, detail string, header ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/sensor/` + slug + `","title":"` + title + `","status":` +
			itoa(status) + `,"detail":"` + detail + `"}`))
	}
}

// Each status class is retried with a short jittered backoff or waited out
// (at least 5 minutes), never returned in daemon mode; the CLI (no
// RetryTransient) returns an error that prints the problem's title and detail.
func TestPairStatusClasses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		reply func(http.ResponseWriter)
		retry bool
	}{
		{"408", statusReply(408), true},
		{"425", statusReply(425), true},
		{"500", statusReply(500), true},
		{"502", statusReply(502), true},
		{"503", statusReply(503), true},
		{"504", statusReply(504), true},
		{"key busy", problemReply(409, "pairing-key-busy", "Key busy", "another request holds it"), true},
		{"400", problemReply(400, "invalid-request", "Bad request", "the host name is too long"), false},
		{"401", problemReply(401, "unauthenticated", "Not signed", "x"), false},
		{"403", problemReply(403, "forbidden", "Forbidden", "x"), false},
		{"404", problemReply(404, "pairing-not-found", "Not found", "x"), false},
		{"409 other", problemReply(409, "conflict", "Conflict", "x"), false},
		{"410", statusReply(410), false},
		{"422", problemReply(422, "invalid-request", "Unprocessable", "x"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			f.startReplies = []func(http.ResponseWriter){tc.reply}
			var out bytes.Buffer
			o := opts(t, srv, &out)
			o.RetryTransient = true
			var sleeps []time.Duration
			o.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
			if _, err := Pair(context.Background(), o); err != nil {
				t.Fatalf("daemon mode must not exit: %v", err)
			}
			if f.starts != 2 || len(sleeps) == 0 {
				t.Fatalf("starts=%d sleeps=%v", f.starts, sleeps)
			}
			d := sleeps[0]
			switch {
			case tc.retry && (d < 2500*time.Millisecond || d > 5*time.Second):
				t.Fatalf("a retryable answer waited %v, want [2.5s, 5s]", d)
			case !tc.retry && (d < 5*time.Minute || d > 7*time.Minute+30*time.Second):
				t.Fatalf("a non-retryable answer waited %v, want [5m, 7.5m]", d)
			}
			if !tc.retry && !strings.Contains(out.String(), "Pairing refused") {
				t.Fatalf("no explanation:\n%s", out.String())
			}
		})
	}
}

// The CLI exits with the problem's title and detail (the raw answer when it
// is not a problem document), and never waits.
func TestPairCLIPrintsTheProblem(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){problemReply(400, "invalid-request", "Bad request", "the host name is too long")}
	_, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{}))
	if err == nil || !strings.Contains(err.Error(), "Bad request: the host name is too long") || f.starts != 1 {
		t.Fatalf("err = %v, starts=%d", err, f.starts)
	}
	f.startReplies = []func(http.ResponseWriter){statusReply(http.StatusTeapot)}
	if _, err = Pair(context.Background(), opts(t, srv, &bytes.Buffer{})); err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("raw fallback: %v", err)
	}
}

// Retry-After is honored (never earlier, with jitter, clamped to 300 s) on
// pairing-key-busy and on a 503.
func TestPairRetryAfterIsHonoured(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reply  func(http.ResponseWriter)
		lo, hi time.Duration
	}{
		{"key busy 7s", problemReply(409, "pairing-key-busy", "Busy", "x", "Retry-After", "7"), 7 * time.Second, 10500 * time.Millisecond},
		{"503 30s", statusReply(503, "Retry-After", "30"), 30 * time.Second, 45 * time.Second},
		{"clamped to 300s", problemReply(409, "pairing-key-busy", "Busy", "x", "Retry-After", "99999"), 300 * time.Second, 450 * time.Second},
		{"zero is not honored", problemReply(409, "pairing-key-busy", "Busy", "x", "Retry-After", "0"), 2500 * time.Millisecond, 5 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			f.startReplies = []func(http.ResponseWriter){tc.reply}
			o := opts(t, srv, &bytes.Buffer{})
			o.RetryTransient = true
			var sleeps []time.Duration
			o.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
			if _, err := Pair(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if len(sleeps) == 0 || sleeps[0] < tc.lo || sleeps[0] > tc.hi {
				t.Fatalf("sleeps %v, want [%v, %v]", sleeps, tc.lo, tc.hi)
			}
		})
	}
}

// A 429 is waited out for the advised delay with a message (it used to be
// silent).
func TestPairRateLimitIsReported(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){statusReply(http.StatusTooManyRequests, "Retry-After", "37")}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	var sleeps []time.Duration
	o.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if len(sleeps) == 0 || sleeps[0] < 37*time.Second || sleeps[0] > 56*time.Second ||
		!strings.Contains(out.String(), "Rate limited by the platform (HTTP 429); retrying in ") {
		t.Fatalf("sleeps %v, output:\n%s", sleeps, out.String())
	}
}

// Final answers are never retried: a refused enrollment token, a 400.
func TestPairDoesNotRetryFinalRefusals(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.refuseToken = true
	o := opts(t, srv, &bytes.Buffer{})
	o.RetryTransient, o.EnrollmentToken = true, "octe_test"
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrEnrollmentRefused) || f.starts != 1 {
		t.Fatalf("refused token: %v, starts=%d", err, f.starts)
	}
	// A 400 is returned by the CLI, and waited out (not exited) by the daemon.
	f.refuseToken = false
	f.starts = 0
	f.startReplies = []func(http.ResponseWriter){statusReply(http.StatusBadRequest)}
	if _, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{})); err == nil || f.starts != 1 {
		t.Fatalf("400: %v, starts=%d", err, f.starts)
	}
}
