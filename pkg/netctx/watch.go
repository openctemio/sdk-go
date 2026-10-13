package netctx

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// DefaultInterval is how often a Watcher detects again.
const DefaultInterval = 5 * time.Minute

// Options configure a Watcher.
type Options struct {
	Declared Declared
	// Sources are where detection reads (zero value: DefaultSources).
	Sources *Sources
	// Echo is the platform's egress echo (nil: the internet mode is
	// declared, "none" without a default route, or "unknown").
	Echo        Echo
	EchoTimeout time.Duration
	// Scope returns the local policy's targets.allow (nil: no limit). It
	// is called on every refresh, so a reloaded policy applies.
	Scope func() Scope
}

// State is one detection and the report built from it.
type State struct {
	Declared Declared
	Detected Detected
	Egress   Egress
	Report   *Report
	At       time.Time
}

// Watcher detects the host's network facts on demand and on an interval
// and keeps the latest report. It is safe for concurrent use.
type Watcher struct {
	opts Options
	mu   sync.Mutex
	cur  *State
	raw  []byte // the current report's JSON, to notice changes
}

// NewWatcher returns a watcher; nothing is detected until Refresh or Run.
func NewWatcher(o Options) *Watcher {
	if o.Sources == nil {
		s := DefaultSources()
		o.Sources = &s
	}
	return &Watcher{opts: o}
}

// Refresh detects now and reports whether the report changed (the first
// refresh always does).
func (w *Watcher) Refresh(ctx context.Context) (State, bool) {
	det := Detect(*w.opts.Sources)
	eg := ResolveEgress(ctx, w.opts.Declared, det, w.opts.Echo, w.opts.EchoTimeout)
	var scope Scope
	if w.opts.Scope != nil {
		scope = w.opts.Scope()
	}
	st := State{Declared: w.opts.Declared, Detected: det, Egress: eg,
		Report: BuildReport(w.opts.Declared, det, eg, scope), At: time.Now()}
	raw, _ := json.Marshal(st.Report)
	w.mu.Lock()
	defer w.mu.Unlock()
	changed := w.cur == nil || string(raw) != string(w.raw)
	w.cur, w.raw = &st, raw
	return st, changed
}

// Rescope rebuilds the report from the latest detection under the current
// Scope, without detecting again or calling the echo (the local policy
// was reloaded: a narrower policy must narrow the report at once). It
// reports whether the report changed; false before the first refresh.
func (w *Watcher) Rescope() (State, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return State{}, false
	}
	var scope Scope
	if w.opts.Scope != nil {
		scope = w.opts.Scope()
	}
	st := *w.cur
	st.Report = BuildReport(st.Declared, st.Detected, st.Egress, scope)
	raw, _ := json.Marshal(st.Report)
	changed := string(raw) != string(w.raw)
	w.cur, w.raw = &st, raw
	return st, changed
}

// Report is the latest report (nil before the first refresh). The report
// is never modified once returned.
func (w *Watcher) Report() *Report {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return nil
	}
	return w.cur.Report
}

// State is the latest detection (false before the first refresh).
func (w *Watcher) State() (State, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.cur == nil {
		return State{}, false
	}
	return *w.cur, true
}

// Run refreshes every interval (DefaultInterval when ≤ 0) until ctx ends,
// calling onChange (when set) after a refresh that changed the report.
func (w *Watcher) Run(ctx context.Context, interval time.Duration, onChange func(State)) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if st, changed := w.Refresh(ctx); changed && onChange != nil {
				onChange(st)
			}
		}
	}
}
