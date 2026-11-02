package feedrelay

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

type httpErr struct {
	status int
	retry  time.Duration
}

func (e *httpErr) Error() string                 { return fmt.Sprintf("status %d", e.status) }
func (e *httpErr) HTTPStatusCode() int           { return e.status }
func (e *httpErr) RetryAfterHint() time.Duration { return e.retry }

// The relay honors the platform's Retry-After (bounded), asks again soon
// after a served round, and waits long after the platform refused it.
func TestNextPoll(t *testing.T) {
	r := &Relay{cfg: Config{Interval: time.Minute}}
	for name, tc := range map[string]struct {
		served bool
		wait   time.Duration
		err    error
		want   time.Duration
	}{
		"served":                 {served: true, want: minPoll},
		"no round, no hint":      {want: time.Minute},
		"no round, in cycle":     {wait: 15 * time.Second, want: 15 * time.Second},
		"not designated":         {wait: 10 * time.Minute, want: 10 * time.Minute},
		"hint below the floor":   {wait: time.Millisecond, want: minPoll},
		"hint above the ceiling": {wait: 24 * time.Hour, want: maxPoll},
		"429 with Retry-After":   {err: fmt.Errorf("next: %w", &httpErr{status: 429, retry: 90 * time.Second}), want: 90 * time.Second},
		"refused (403)":          {err: &httpErr{status: 403}, want: refusedPoll},
		"other error":            {err: errors.New("network"), want: time.Minute},
		"server error, no hint":  {err: &httpErr{status: 500}, want: time.Minute},
	} {
		if got := r.nextPoll(tc.served, tc.wait, tc.err); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
