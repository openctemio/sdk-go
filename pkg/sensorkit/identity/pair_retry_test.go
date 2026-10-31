package identity

import (
	"bytes"
	"context"
	"errors"
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
// each time, then pairing completes with the same key.
func TestPairRetriesTransientFailuresWithBackoff(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){clockSkewReply(15000)}
	for range 7 {
		f.startReplies = append(f.startReplies, statusReply(http.StatusServiceUnavailable))
	}
	f.startReplies = append(f.startReplies, statusReply(http.StatusUnauthorized))
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.RetryTransient = true
	var sleeps []time.Duration
	o.sleep = func(_ context.Context, d time.Duration) error { sleeps = append(sleeps, d); return nil }
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("pairing after transient failures: %v", err)
	}
	want := []time.Duration{5 * time.Second, 10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
		160 * time.Second, 5 * time.Minute, 5 * time.Minute, 5 * time.Minute}
	if len(sleeps) < len(want) {
		t.Fatalf("sleeps %v", sleeps)
	}
	for i, d := range want {
		if sleeps[i] != d {
			t.Fatalf("backoff %d = %v, want %v (all %v)", i, sleeps[i], d, sleeps)
		}
	}
	if f.starts != 10 || !f.confirmed {
		t.Fatalf("starts=%d confirmed=%v", f.starts, f.confirmed)
	}
	if !strings.Contains(out.String(), "ahead of the platform") || !strings.Contains(out.String(), "Retrying in 5s.") {
		t.Fatalf("output:\n%s", out.String())
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
	if len(sleeps) == 0 || sleeps[0] != 37*time.Second ||
		!strings.Contains(out.String(), "Rate limited by the platform (HTTP 429); retrying in 37s.") {
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
	f.refuseToken = false
	f.starts = 0
	f.startReplies = []func(http.ResponseWriter){statusReply(http.StatusBadRequest)}
	o = opts(t, srv, &bytes.Buffer{})
	o.RetryTransient = true
	if _, err := Pair(context.Background(), o); err == nil || f.starts != 1 {
		t.Fatalf("400: %v, starts=%d", err, f.starts)
	}
}

func problemReply(status int, name string, header ...string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(header); i += 2 {
			w.Header().Set(header[i], header[i+1])
		}
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(status)
		// A detail longer than the part of the body an error keeps: the
		// type is still read.
		_, _ = w.Write([]byte(`{"type":"https://openctem.io/problems/sensor/` + name + `","title":"t","status":` + itoa(status) +
			`,"detail":"` + strings.Repeat("d", 400) + `","retryable":false}`))
	}
}

// A key the platform registered before is a final answer with the fix in
// it, never retried (a retry loop only spends the pairing budget).
func TestPairKeyRegisteredIsFinalAndExplained(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){problemReply(http.StatusConflict, "pairing-key-registered")}
	o := opts(t, srv, &bytes.Buffer{})
	o.RetryTransient, o.Retry = true, true
	_, err := Pair(context.Background(), o)
	if !errors.Is(err, ErrKeyRegistered) || f.starts != 1 {
		t.Fatalf("registered key: %v, starts=%d", err, f.starts)
	}
	for _, want := range []string{"pairs only once", o.Store.Dir(), "new code"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message %q lacks %q", err, want)
		}
	}
}

// A key another open request holds is waited out; any other 409 is final.
func TestPairKeyBusyIsRetried(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){problemReply(http.StatusConflict, "pairing-key-busy", "Retry-After", "30")}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.RetryTransient = true
	if _, err := Pair(context.Background(), o); err != nil || f.starts != 2 {
		t.Fatalf("busy key: %v, starts=%d\n%s", err, f.starts, out.String())
	}
	f.starts = 0
	f.startReplies = []func(http.ResponseWriter){problemReply(http.StatusConflict, "report-conflict")}
	o = opts(t, srv, &bytes.Buffer{})
	o.RetryTransient = true
	if _, err := Pair(context.Background(), o); err == nil || errors.Is(err, ErrKeyRegistered) || f.starts != 1 {
		t.Fatalf("other 409: %v, starts=%d", err, f.starts)
	}
}
