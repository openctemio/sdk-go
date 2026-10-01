package core

// Heartbeat doorbell, sensor side. The API contract is RFC-023 §9.2a
// (api docs/architecture/sensors.md, "Heartbeat doorbell").
//
// The heartbeat response may carry hints: how many jobs this sensor could
// claim now, when to send the next heartbeat, typed actions from a closed set
// and a version of what the platform governs about the sensor. The hints say
// THAT something is waiting, never WHAT: jobs are still fetched and claimed
// through the command poll. Nothing outside the closed action set is ever
// acted on, and no hint can make the sensor run a command line (R-4).

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HeartbeatAction is a typed directive the platform may send on a heartbeat.
type HeartbeatAction string

// The closed set of heartbeat actions. Any other value is ignored.
const (
	// HeartbeatActionPause: stop claiming and starting new jobs; running jobs
	// finish and heartbeats continue. Lifted by the first heartbeat answer
	// without pause (or by resume).
	HeartbeatActionPause HeartbeatAction = "pause"
	// HeartbeatActionResume lifts a pause explicitly.
	HeartbeatActionResume HeartbeatAction = "resume"
	// HeartbeatActionDrain is pause that is not lifted for the rest of the
	// process lifetime: the sensor finishes its running jobs and takes no
	// more until it is restarted.
	HeartbeatActionDrain HeartbeatAction = "drain"
	// HeartbeatActionRotateKey: the presented API key is inside its renewal
	// window; renew it now.
	HeartbeatActionRotateKey HeartbeatAction = "rotate_key"
	// HeartbeatActionUpdate: a newer sensor build is available. Only logged:
	// the SDK never downloads or executes anything because of it.
	HeartbeatActionUpdate HeartbeatAction = "update"
)

// Client-side bounds on the heartbeat delay the platform advises. The server
// already clamps its advice; these only protect the sensor (and the platform)
// from a broken or hostile answer.
const (
	MinDoorbellHeartbeatInterval = 5 * time.Second
	MaxDoorbellHeartbeatInterval = 5 * time.Minute
	// MaxDoorbellPendingJobs is the most pending_jobs the server reports.
	MaxDoorbellPendingJobs = 100
	// DefaultDoorbellSafetyPoll is how often a doorbell-driven poller still
	// polls on its own, in case a heartbeat answer that would have rung the
	// doorbell was lost.
	DefaultDoorbellSafetyPoll = 5 * time.Minute
	// maxConfigVersionLen bounds config_version (16 hex chars today).
	maxConfigVersionLen = 64
	// maxUnknownActionsLogged bounds the memory used to log each unknown
	// action only once.
	maxUnknownActionsLogged = 32
)

// HeartbeatHints is the doorbell part of a heartbeat response. A server
// without the doorbell sends none of these fields; Present is then false.
type HeartbeatHints struct {
	// Present is true when the response carried at least one doorbell field.
	// A server that knows the doorbell answers every heartbeat of a
	// doorbell-aware sensor with at least next_heartbeat_seconds.
	Present bool
	// PendingJobs is the number of jobs this sensor could claim now (0..100).
	PendingJobs int
	// NextHeartbeat is the advised delay before the next heartbeat, already
	// clamped to [MinDoorbellHeartbeatInterval, MaxDoorbellHeartbeatInterval].
	// Zero when not advised.
	NextHeartbeat time.Duration
	// Actions are the actions the server sent, unfiltered. Doorbell.Handle
	// acts only on the known ones.
	Actions []HeartbeatAction
	// ConfigVersion is the opaque version of what the platform governs about
	// this sensor, or "" when absent or malformed.
	ConfigVersion string
}

// heartbeatHintsWire is the JSON shape of the hints in a heartbeat response.
type heartbeatHintsWire struct {
	PendingJobs          *int     `json:"pending_jobs"`
	NextHeartbeatSeconds *int     `json:"next_heartbeat_seconds"`
	Actions              []string `json:"actions"`
	ConfigVersion        *string  `json:"config_version"`
}

// ParseHeartbeatHints reads the doorbell hints from a heartbeat response
// body. Fields outside their documented range are dropped, never trusted. A
// body that is not a JSON object yields no hints (Present=false).
func ParseHeartbeatHints(body []byte) *HeartbeatHints {
	h := &HeartbeatHints{}
	var w heartbeatHintsWire
	if len(body) == 0 || json.Unmarshal(body, &w) != nil {
		return h
	}
	if w.PendingJobs != nil {
		h.Present = true
		if n := *w.PendingJobs; n > 0 {
			h.PendingJobs = min(n, MaxDoorbellPendingJobs)
		}
	}
	if w.NextHeartbeatSeconds != nil {
		h.Present = true
		if s := *w.NextHeartbeatSeconds; s > 0 {
			d := time.Duration(min(s, int(MaxDoorbellHeartbeatInterval/time.Second))) * time.Second
			h.NextHeartbeat = min(max(d, MinDoorbellHeartbeatInterval), MaxDoorbellHeartbeatInterval)
		}
	}
	if w.Actions != nil {
		h.Present = true
		for _, a := range w.Actions {
			h.Actions = append(h.Actions, HeartbeatAction(a))
		}
	}
	if w.ConfigVersion != nil {
		h.Present = true
		if validConfigVersion(*w.ConfigVersion) {
			h.ConfigVersion = *w.ConfigVersion
		}
	}
	return h
}

func validConfigVersion(v string) bool {
	if v == "" || len(v) > maxConfigVersionLen {
		return false
	}
	for _, r := range v {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}

// DoorbellPusher is a Pusher whose heartbeat announces the doorbell and
// returns the hints. *client.Client implements it.
type DoorbellPusher interface {
	SendHeartbeatWithHints(ctx context.Context, status *SensorStatus) (*HeartbeatHints, error)
}

// DoorbellConfig configures a Doorbell.
type DoorbellConfig struct {
	// OnRotateKey is called (in its own goroutine) when the platform sends
	// rotate_key, e.g. platform.KeyRenewManager.RenewNow. Nil: rotate_key is
	// logged and otherwise ignored.
	OnRotateKey func()
	// Logger receives the doorbell's state changes. Nil logs to stderr with
	// timestamps.
	Logger *log.Logger
	// Verbose also logs every heartbeat's hints.
	Verbose bool
}

// Doorbell holds what the platform said on the last heartbeat and turns it
// into sensor behavior: it wakes the command poller when work is waiting,
// pauses and resumes job intake, and triggers key renewal. One Doorbell is
// shared by the heartbeat loop (which calls Handle) and the poller (which
// reads Paused, HintsActive and Wake). Safe for concurrent use.
type Doorbell struct {
	cfg  DoorbellConfig
	logf func(format string, args ...any)

	mu            sync.Mutex
	hintsActive   bool
	paused        bool
	draining      bool
	configVersion string
	pendingJobs   int
	updateLogged  bool
	unknownLogged map[string]bool

	// wake carries at most one pending "poll now".
	wake chan struct{}

	// authGate is the heartbeat's AuthGate, attached by
	// BaseSensor.SetDoorbell so a poller sharing this doorbell can tell
	// that the platform rejects the key.
	authGate *AuthGate
}

// NewDoorbell creates a Doorbell. A nil config uses defaults.
func NewDoorbell(cfg *DoorbellConfig) *Doorbell {
	if cfg == nil {
		cfg = &DoorbellConfig{}
	}
	lg := cfg.Logger
	if lg == nil {
		lg = log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds)
	}
	return &Doorbell{
		cfg:           *cfg,
		logf:          func(format string, args ...any) { lg.Printf("[doorbell] "+format, args...) },
		unknownLogged: make(map[string]bool),
		wake:          make(chan struct{}, 1),
	}
}

// Handle applies one heartbeat answer. A nil hints value (or one with
// Present=false) means the server does not speak the doorbell: the poller
// falls back to its fixed interval.
func (d *Doorbell) Handle(h *HeartbeatHints) {
	if h == nil {
		h = &HeartbeatHints{}
	}
	var (
		pause, resume, drain, rotate, update bool
		unknown                              []string
	)
	for _, a := range h.Actions {
		switch a {
		case HeartbeatActionPause:
			pause = true
		case HeartbeatActionResume:
			resume = true
		case HeartbeatActionDrain:
			drain = true
		case HeartbeatActionRotateKey:
			rotate = true
		case HeartbeatActionUpdate:
			update = true
		default:
			unknown = append(unknown, string(a))
		}
	}

	d.mu.Lock()
	wasActive := d.hintsActive
	d.hintsActive = h.Present
	if wasActive != h.Present {
		if h.Present {
			d.logf("server sends heartbeat hints: polling on the doorbell (safety poll every %v)", DefaultDoorbellSafetyPoll)
		} else {
			d.logf("server sends no heartbeat hints: fixed-interval polling")
		}
	}
	if d.cfg.Verbose && h.Present {
		d.logf("hints: pending_jobs=%d next_heartbeat=%v actions=%s config_version=%s",
			h.PendingJobs, h.NextHeartbeat, quoteList(actionStrings(h.Actions)), h.ConfigVersion)
	}

	if drain && !d.draining {
		d.draining = true
		d.logf("draining by platform: no new jobs until restart; running jobs finish")
	}
	// The pause holds while the platform keeps sending it: the first answer
	// without pause lifts it (resume says so explicitly). pause wins over
	// resume in the same answer, the safe side. Drain is never lifted.
	wasPaused := d.paused
	d.paused = pause
	switch {
	case pause && !wasPaused:
		d.logf("paused by platform: no new jobs; running jobs finish, heartbeats continue")
	case !pause && wasPaused && !d.draining:
		d.logf("resumed by platform: taking jobs again")
	case resume && !pause && d.draining:
		d.logf("ignoring resume: draining is final until the sensor restarts")
	}

	if h.ConfigVersion != "" && h.ConfigVersion != d.configVersion {
		if d.configVersion == "" {
			d.logf("config version %s", h.ConfigVersion)
		} else {
			d.logf("config version changed %s -> %s (the platform changed this sensor's settings)", d.configVersion, h.ConfigVersion)
		}
		d.configVersion = h.ConfigVersion
	}

	if update && !d.updateLogged {
		d.logf("platform reports a sensor update is available (not applied automatically)")
	}
	d.updateLogged = update

	for _, u := range unknown {
		if !d.unknownLogged[u] && len(d.unknownLogged) < maxUnknownActionsLogged {
			d.unknownLogged[u] = true
			d.logf("ignoring unknown heartbeat action %s", quote(u))
		}
	}

	takingJobs := !d.paused && !d.draining
	d.pendingJobs = h.PendingJobs
	d.mu.Unlock()

	if h.PendingJobs > 0 && takingJobs {
		d.ring()
	}
	if rotate {
		if d.cfg.OnRotateKey != nil {
			d.logf("platform asks for key rotation: renewing now")
			go d.cfg.OnRotateKey()
		} else {
			d.logf("platform asks for key rotation, but key renewal is not enabled on this sensor")
		}
	}
}

// HeartbeatFailed records that a heartbeat got no answer. The doorbell can
// no longer ring, so the poller returns to its fixed interval until the next
// answered heartbeat. Pause and drain are kept.
func (d *Doorbell) HeartbeatFailed() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.hintsActive {
		d.hintsActive = false
		d.logf("heartbeat failed: fixed-interval polling until the next answered heartbeat")
	}
}

// heartbeatRejected records a heartbeat the platform rejected for
// authentication: the hints are no longer valid. Unlike HeartbeatFailed it
// logs nothing, because polling stops (the AuthGate logs) rather than
// falling back to the fixed interval.
func (d *Doorbell) heartbeatRejected() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hintsActive = false
}

func (d *Doorbell) setAuthGate(g *AuthGate) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.authGate = g
}

func (d *Doorbell) getAuthGate() *AuthGate {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.authGate
}

func (d *Doorbell) ring() {
	select {
	case d.wake <- struct{}{}:
	default: // a wake is already pending
	}
}

// Wake fires when the platform reported claimable work.
func (d *Doorbell) Wake() <-chan struct{} { return d.wake }

// HintsActive reports whether the last heartbeat answer carried hints, i.e.
// the poller may rely on the doorbell instead of polling on a fixed interval.
func (d *Doorbell) HintsActive() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.hintsActive
}

// Paused reports whether the sensor must not claim or start new jobs
// (pause or drain).
func (d *Doorbell) Paused() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.paused || d.draining
}

// Draining reports whether the platform drained this sensor.
func (d *Doorbell) Draining() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.draining
}

// ConfigVersion returns the last config version the platform sent, or "".
func (d *Doorbell) ConfigVersion() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.configVersion
}

// PendingJobs returns pending_jobs from the last heartbeat answer.
func (d *Doorbell) PendingJobs() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.pendingJobs
}

// State is a one-line, human-readable job-intake state for status output.
func (d *Doorbell) State() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case d.draining:
		return "draining by platform"
	case d.paused:
		return "paused by platform"
	default:
		return "running"
	}
}

// quote renders a server-supplied value for a log line: quoted (so control
// characters and line breaks are escaped) and bounded.
func quote(s string) string {
	const maxLen = 64
	if len(s) > maxLen {
		s = s[:maxLen] + "..."
	}
	q := strconv.Quote(s)
	q = strings.ReplaceAll(q, "\n", "")
	return strings.ReplaceAll(q, "\r", "")
}

func quoteList(ss []string) string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		out = append(out, quote(s))
	}
	return fmt.Sprintf("[%s]", strings.Join(out, ","))
}

func actionStrings(as []HeartbeatAction) []string {
	out := make([]string, 0, len(as))
	for _, a := range as {
		out = append(out, string(a))
	}
	return out
}
