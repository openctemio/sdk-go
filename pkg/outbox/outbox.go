// Package outbox is the sensor's durable, write-ahead queue of results waiting
// for the platform.
//
// Every result (a CTIS report, a v1 chunk, a command result) is written to the
// outbox BEFORE the first attempt to send it, and removed only after the
// platform acknowledged it (2xx). A crash, kill -9 or restart loses nothing:
// the next process resumes from the files.
//
// Storage is one directory, used by one process at a time (flock):
//
//	<dir>/outbox.key        AES-256-GCM key, 0600, generated on first use
//	<dir>/pending/<id>.item the result (sealed, immutable)
//	<dir>/pending/<id>.state its delivery state (sealed, rewritten per attempt)
//	<dir>/dead/             results the platform refused for good, with
//	                        <id>.reason.json (plain JSON) saying why
//	<dir>/corrupt/          files that failed authentication (torn writes,
//	                        foreign files, a lost key), quarantined
//	<dir>/tmp/              temporary files of in-progress writes
//
// Every file is 0600 and every directory 0700. Writes are crash-safe (write a
// temporary file, fsync, rename, fsync the directory). Files are sealed with
// AES-256-GCM, which also detects a torn or corrupted file: it is moved to
// corrupt/ and never crashes the process or blocks the queue.
//
// The outbox never fills the disk: a byte cap (default 1 GiB, and never more
// than a fraction of the free space) and an age cap (default 7 days) evict the
// oldest entries first (dead letters before pending results), with a log line,
// a counter and a callback the caller turns into a heartbeat warning.
//
// Delivery is the caller's: Run hands each item, oldest first, to a
// Deliverer, which classifies the outcome by the error it returns (see
// Permanent, RetryAfter, Unauthorized). Transient failures back off with
// jitter behind a circuit breaker; Wake (the platform answered a heartbeat
// again) drains at once; Unauthorized pauses all delivery until Wake or
// Resume.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Defaults.
const (
	DefaultMaxBytes = 1 << 30 // 1 GiB
	// DefaultMaxDiskFraction caps the outbox at this fraction of the space it
	// could use (its own bytes plus the free space), so a small disk is never
	// filled even below MaxBytes.
	DefaultMaxDiskFraction = 0.5
	DefaultMaxAge          = 7 * 24 * time.Hour
	DefaultConcurrency     = 1
	MaxConcurrency         = 2

	// DefaultBackoffBase and DefaultBackoffMax bound the per-item retry delay
	// after a transient failure (exponential, full jitter in [d/2, d]).
	DefaultBackoffBase = 2 * time.Second
	DefaultBackoffMax  = 5 * time.Minute
	// DefaultCircuitThreshold consecutive transient failures open the circuit:
	// no delivery until the cool-down passes or Wake is called.
	DefaultCircuitThreshold = 3
	// maxRetryAfter caps a server's Retry-After.
	maxRetryAfter = time.Hour
	// maxStateFile and maxReasonFile bound what is read back from disk.
	maxStateFile  = 1 << 20
	maxReasonFile = 1 << 20
	// maxCorruptKept bounds the quarantine.
	maxCorruptKept = 200
)

// Errors.
var (
	// ErrLocked: another process holds the outbox directory.
	ErrLocked = errors.New("outbox: directory is in use by another process")
	// ErrClosed: the outbox was closed.
	ErrClosed = errors.New("outbox: closed")
	// ErrTooLarge: one item is larger than the outbox may ever hold.
	ErrTooLarge = errors.New("outbox: item larger than the outbox byte cap")
)

// Kind is what an item carries.
type Kind string

const (
	// KindReport is a CTIS report (findings and/or assets).
	KindReport Kind = "report"
	// KindCommandResult is the completion or failure of a platform command.
	// It is delivered only after every older report of the same command.
	KindCommandResult Kind = "command_result"
	// KindChunk is one protocol v1 chunk of a large report (pkg/chunk).
	KindChunk Kind = "chunk"
)

// Meta describes an item. It is fixed when the item is enqueued.
type Meta struct {
	// ID is a UUIDv7 and the file name. Enqueue assigns it.
	ID   string `json:"id"`
	Kind Kind   `json:"kind"`
	// ReportID is the stable report id (UUIDv7) the v2 protocol uses as the
	// idempotency key. Enqueue assigns one to a KindReport item that has none.
	ReportID string `json:"report_id,omitempty"`
	// CommandID binds the item to a platform command.
	CommandID string `json:"command_id,omitempty"`
	// CreatedAt orders the items (oldest first). Enqueue sets it.
	CreatedAt time.Time `json:"created_at"`
	// Attrs are free-form small strings for the deliverer.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// State is an item's delivery state, persisted after every attempt.
type State struct {
	Attempts    int       `json:"attempts"`
	NextAttempt time.Time `json:"next_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
	// RateLimited: the last failure carried a Retry-After, which Wake does
	// not override.
	RateLimited bool `json:"rate_limited,omitempty"`
	// Progress is owned by the deliverer (for example the v2 segments the
	// server already acknowledged); see Delivery.SaveProgress.
	Progress json.RawMessage `json:"progress,omitempty"`
}

// DeadLetter is an item the platform refused for good.
type DeadLetter struct {
	Meta   Meta      `json:"meta"`
	DeadAt time.Time `json:"dead_at"`
	// Status is the HTTP status of the refusal (0 when the SDK refused it).
	Status int `json:"status,omitempty"`
	// Reason is a one-line explanation.
	Reason string `json:"reason"`
	// Problem is the server's RFC 9457 problem document, when it sent one.
	Problem json.RawMessage `json:"problem,omitempty"`
	// Attempts made before the refusal.
	Attempts int `json:"attempts"`
}

// Config configures an outbox. Dir is required; zero values use the
// defaults.
type Config struct {
	// Dir is the outbox directory. It is created 0700 if missing.
	Dir string
	// KeyFile is the encryption key file. Default: <Dir>/outbox.key. Point it
	// outside Dir (a mounted secret) to keep the key off the data volume.
	KeyFile string
	// MaxBytes caps the bytes on disk (pending + dead letters). Default 1 GiB.
	MaxBytes int64
	// MaxDiskFraction caps the outbox at this fraction of (its own bytes +
	// the free space). Default 0.5. Negative disables the free-space cap.
	MaxDiskFraction float64
	// MaxAge evicts pending items and dead letters older than this. Default
	// 7 days.
	MaxAge time.Duration
	// Concurrency is how many items are delivered at once (1 or 2). Default 1.
	Concurrency int
	// BackoffBase and BackoffMax bound the per-item retry delay.
	BackoffBase time.Duration
	BackoffMax  time.Duration
	// CircuitThreshold is the number of consecutive transient failures that
	// pause all delivery until the back-off passes or Wake is called.
	CircuitThreshold int
	// Logf receives the outbox's log lines (state changes, evictions,
	// quarantines, dead letters). Default: the standard logger.
	Logf func(format string, args ...any)
	// OnEvict is called (without locks held) after items were evicted to
	// respect the caps.
	OnEvict func(evicted []Meta, reason string)
	// OnDeadLetter is called (without locks held) when an item is
	// dead-lettered.
	OnDeadLetter func(DeadLetter)

	// now is the clock (tests).
	now func() time.Time
}

func (c *Config) withDefaults() Config {
	out := *c
	if out.KeyFile == "" {
		out.KeyFile = filepath.Join(out.Dir, keyName)
	}
	if out.MaxBytes <= 0 {
		out.MaxBytes = DefaultMaxBytes
	}
	if out.MaxDiskFraction == 0 {
		out.MaxDiskFraction = DefaultMaxDiskFraction
	}
	if out.MaxDiskFraction > 1 {
		out.MaxDiskFraction = 1
	}
	if out.MaxAge <= 0 {
		out.MaxAge = DefaultMaxAge
	}
	if out.Concurrency <= 0 {
		out.Concurrency = DefaultConcurrency
	}
	if out.Concurrency > MaxConcurrency {
		out.Concurrency = MaxConcurrency
	}
	if out.BackoffBase <= 0 {
		out.BackoffBase = DefaultBackoffBase
	}
	if out.BackoffMax <= 0 {
		out.BackoffMax = DefaultBackoffMax
	}
	if out.BackoffMax < out.BackoffBase {
		out.BackoffMax = out.BackoffBase
	}
	if out.CircuitThreshold <= 0 {
		out.CircuitThreshold = DefaultCircuitThreshold
	}
	if out.Logf == nil {
		lg := log.New(os.Stderr, "", log.LstdFlags)
		out.Logf = func(format string, args ...any) { lg.Printf("[outbox] "+format, args...) }
	}
	if out.now == nil {
		out.now = time.Now
	}
	return out
}

// entry is the in-memory index of one item.
type entry struct {
	meta      Meta
	state     State
	itemSize  int64
	stateSize int64
	dead      *DeadLetter
	inflight  bool
}

func (e *entry) size() int64 { return e.itemSize + e.stateSize }

// Result is the final outcome of one item, sent on its Ticket.
type Result struct {
	// Delivered: the platform acknowledged the item.
	Delivered bool
	// Value is what the Deliverer returned with the acknowledgement.
	Value any
	// Dead is set when the item was dead-lettered.
	Dead *DeadLetter
	// Evicted: the item was dropped by the size or age cap.
	Evicted bool
}

// Ticket follows one enqueued item.
type Ticket struct {
	Meta Meta
	done chan Result
}

// Done delivers the item's final Result once (buffered; never blocks the
// outbox).
func (t *Ticket) Done() <-chan Result { return t.done }

// Outbox is a durable queue. Safe for concurrent use.
type Outbox struct {
	cfg    Config
	seal   *sealer
	unlock func()

	pendingDir, deadDir, corruptDir, tmpDir string

	mu       sync.Mutex
	entries  map[string]*entry
	watchers map[string]chan Result
	changed  chan struct{} // closed and replaced on every state change
	closed   bool

	// delivery control
	authPaused      bool
	authErr         string
	consecutiveFail int
	circuitUntil    time.Time

	// counters since Open
	evicted     int64
	corrupt     int64
	delivered   int64
	deadLetters int64
	attempts    int64
	lastEvictAt time.Time
}

// Open opens (creating if needed) the outbox directory, takes its lock,
// loads the key and indexes the items. Items that fail authentication are
// quarantined; Open fails only when the directory cannot be used at all.
func Open(cfg Config) (*Outbox, error) {
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, errors.New("outbox: Dir is required")
	}
	c := cfg.withDefaults()
	o := &Outbox{
		cfg:        c,
		pendingDir: filepath.Join(c.Dir, dirPending),
		deadDir:    filepath.Join(c.Dir, dirDead),
		corruptDir: filepath.Join(c.Dir, dirCorrupt),
		tmpDir:     filepath.Join(c.Dir, dirTmp),
		entries:    map[string]*entry{},
		watchers:   map[string]chan Result{},
		changed:    make(chan struct{}),
	}
	if err := os.MkdirAll(c.Dir, dirMode); err != nil {
		return nil, fmt.Errorf("outbox: create %s: %w", c.Dir, err)
	}
	if fi, err := os.Stat(c.Dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(c.Dir, dirMode); err != nil {
			c.Logf("cannot restrict %s to 0700: %v", c.Dir, err)
		}
	}
	unlock, err := lockDir(filepath.Join(c.Dir, lockName))
	if err != nil {
		if errors.Is(err, ErrLocked) {
			return nil, fmt.Errorf("%w: %s", ErrLocked, c.Dir)
		}
		return nil, err
	}
	o.unlock = unlock
	ok := false
	defer func() {
		if !ok {
			unlock()
		}
	}()
	for _, d := range []string{o.pendingDir, o.deadDir, o.corruptDir, o.tmpDir} {
		if err := os.MkdirAll(d, dirMode); err != nil {
			return nil, fmt.Errorf("outbox: create %s: %w", d, err)
		}
		_ = os.Chmod(d, dirMode)
	}
	// Leftovers of writes interrupted by a crash.
	if names, err := os.ReadDir(o.tmpDir); err == nil {
		for _, n := range names {
			_ = os.Remove(filepath.Join(o.tmpDir, n.Name()))
		}
	}
	key, created, err := loadOrCreateKey(c.KeyFile, o.tmpDir)
	if err != nil {
		return nil, err
	}
	if o.seal, err = newSealer(key); err != nil {
		return nil, err
	}
	if err := o.load(); err != nil {
		return nil, err
	}
	if created && o.corrupt > 0 {
		c.Logf("a new encryption key was created at %s while sealed items existed: %d item(s) could not be read and were quarantined in %s",
			c.KeyFile, o.corrupt, o.corruptDir)
	}
	o.trimCorrupt()
	evicted, reason := o.enforceCapsLocked(0)
	o.notifyEvicted(evicted, reason)
	ok = true
	return o, nil
}

// load indexes pending/ and dead/.
func (o *Outbox) load() error {
	for _, dead := range []bool{false, true} {
		dir := o.pendingDir
		if dead {
			dir = o.deadDir
		}
		names, err := os.ReadDir(dir)
		if err != nil {
			return fmt.Errorf("outbox: read %s: %w", dir, err)
		}
		items := map[string]bool{}
		states := map[string]bool{}
		for _, n := range names {
			name := n.Name()
			switch {
			case strings.HasSuffix(name, itemExt):
				items[strings.TrimSuffix(name, itemExt)] = true
			case strings.HasSuffix(name, stateExt):
				states[strings.TrimSuffix(name, stateExt)] = true
			case strings.HasSuffix(name, reasonExt):
			default:
				o.quarantine(filepath.Join(dir, name), "unexpected file")
			}
		}
		for id := range states {
			if !items[id] {
				// The item was delivered (or quarantined) and the crash came
				// before its state file was removed.
				_ = removeFiles(filepath.Join(dir, id+stateExt), filepath.Join(dir, id+reasonExt))
			}
		}
		for id := range items {
			if !validID(id) {
				o.quarantine(filepath.Join(dir, id+itemExt), "invalid file name")
				o.quarantine(filepath.Join(dir, id+stateExt), "invalid file name")
				continue
			}
			e, err := o.loadEntry(dir, id, states[id])
			if err != nil {
				o.cfg.Logf("item %s is unreadable (%v): quarantined in %s", id, err, o.corruptDir)
				o.quarantine(filepath.Join(dir, id+itemExt), "")
				o.quarantine(filepath.Join(dir, id+stateExt), "")
				_ = removeFiles(filepath.Join(dir, id+reasonExt))
				continue
			}
			if dead {
				e.dead = o.readReason(id, e)
			}
			o.entries[id] = e
		}
	}
	return nil
}

func validID(id string) bool {
	u, err := uuid.Parse(id)
	return err == nil && u.String() == id
}

// loadEntry reads one item's index entry from its state file, or from the
// item itself when the state is missing or unreadable (a crash between the
// two writes of Enqueue, or a torn state file).
func (o *Outbox) loadEntry(dir, id string, hasState bool) (*entry, error) {
	itemPath := filepath.Join(dir, id+itemExt)
	fi, err := os.Stat(itemPath)
	if err != nil {
		return nil, err
	}
	e := &entry{itemSize: fi.Size()}
	statePath := filepath.Join(dir, id+stateExt)
	if hasState {
		if data, err := readAllLimited(statePath, maxStateFile); err == nil {
			if pt, err := o.seal.open(typeState, id, data); err == nil {
				var sf stateFile
				if json.Unmarshal(pt, &sf) == nil && sf.Meta.ID == id {
					if sf.ItemSize != 0 && sf.ItemSize != e.itemSize {
						return nil, fmt.Errorf("item is %d bytes, %d were written", e.itemSize, sf.ItemSize)
					}
					e.meta, e.state, e.stateSize = sf.Meta, sf.State, int64(len(data))
					return e, nil
				}
			}
		}
		o.cfg.Logf("state of item %s is unreadable: rebuilt from the item (delivery restarts from the first attempt)", id)
		o.quarantine(statePath, "")
	}
	// Rebuild from the item. Its full authentication is the check that the
	// item itself is intact.
	data, err := os.ReadFile(itemPath) //nolint:gosec // outbox directory
	if err != nil {
		return nil, err
	}
	pt, err := o.seal.open(typeItem, id, data)
	if err != nil {
		return nil, err
	}
	m, _, err := decodeItem(pt, false)
	if err != nil || m.ID != id {
		return nil, errCorrupt
	}
	e.meta = m
	if err := o.writeState(dir, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (o *Outbox) readReason(id string, e *entry) *DeadLetter {
	dl := &DeadLetter{Meta: e.meta, Reason: "unknown (reason file missing)", Attempts: e.state.Attempts}
	if data, err := readAllLimited(filepath.Join(o.deadDir, id+reasonExt), maxReasonFile); err == nil {
		var r DeadLetter
		if json.Unmarshal(data, &r) == nil {
			r.Meta = e.meta
			return &r
		}
	}
	if fi, err := os.Stat(filepath.Join(o.deadDir, id+itemExt)); err == nil {
		dl.DeadAt = fi.ModTime()
	}
	return dl
}

// quarantine moves a file to corrupt/ (or removes it when that fails).
func (o *Outbox) quarantine(path, why string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	if why != "" {
		o.cfg.Logf("%s: %s quarantined in %s", why, filepath.Base(path), o.corruptDir)
	}
	dst := filepath.Join(o.corruptDir, fmt.Sprintf("%d-%s", o.cfg.now().UnixNano(), filepath.Base(path)))
	if err := os.Rename(path, dst); err != nil {
		_ = os.Remove(path)
	}
	_ = syncDir(filepath.Dir(path))
	_ = syncDir(o.corruptDir)
	o.corrupt++
}

// trimCorrupt keeps the quarantine bounded (count and age).
func (o *Outbox) trimCorrupt() {
	names, err := os.ReadDir(o.corruptDir)
	if err != nil {
		return
	}
	sort.Slice(names, func(i, j int) bool { return names[i].Name() < names[j].Name() })
	cutoff := o.cfg.now().Add(-o.cfg.MaxAge)
	for i, n := range names {
		info, err := n.Info()
		if err != nil {
			continue
		}
		if len(names)-i > maxCorruptKept || info.ModTime().Before(cutoff) {
			_ = os.Remove(filepath.Join(o.corruptDir, n.Name()))
		}
	}
}

// writeState persists e's state. Caller holds o.mu or owns e exclusively.
func (o *Outbox) writeState(dir string, e *entry) error {
	pt, err := json.Marshal(stateFile{Meta: e.meta, State: e.state, ItemSize: e.itemSize})
	if err != nil {
		return err
	}
	data, err := o.seal.seal(typeState, e.meta.ID, pt)
	if err != nil {
		return err
	}
	if err := writeAtomic(o.tmpDir, dir, e.meta.ID+stateExt, data); err != nil {
		return err
	}
	e.stateSize = int64(len(data))
	return nil
}

// Enqueue durably stores an item and returns its ticket. When it returns nil
// the item is on disk (fsynced) and will be delivered even if the process
// dies now. Meta.ID and Meta.CreatedAt are assigned; a KindReport without a
// ReportID gets one.
func (o *Outbox) Enqueue(m Meta, payload []byte) (*Ticket, error) {
	if m.Kind == "" {
		return nil, errors.New("outbox: Meta.Kind is required")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, fmt.Errorf("outbox: id: %w", err)
	}
	m.ID = id.String()
	m.CreatedAt = o.cfg.now().UTC()
	if m.Kind == KindReport && m.ReportID == "" {
		rid, err := uuid.NewV7()
		if err != nil {
			return nil, fmt.Errorf("outbox: report id: %w", err)
		}
		m.ReportID = rid.String()
	}
	pt, err := encodeItem(m, payload)
	if err != nil {
		return nil, err
	}
	data, err := o.seal.seal(typeItem, m.ID, pt)
	if err != nil {
		return nil, err
	}
	e := &entry{meta: m, itemSize: int64(len(data))}

	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil, ErrClosed
	}
	limit := o.capBytesLocked()
	if e.itemSize > limit {
		o.mu.Unlock()
		return nil, fmt.Errorf("%w (%d bytes > %d)", ErrTooLarge, e.itemSize, limit)
	}
	// Make room first (oldest out), then write. The state file is small; the
	// item size is what counts.
	evicted, reason := o.enforceCapsLocked(e.itemSize + 512)
	if err := writeAtomic(o.tmpDir, o.pendingDir, m.ID+itemExt, data); err != nil {
		o.mu.Unlock()
		o.notifyEvicted(evicted, reason)
		return nil, fmt.Errorf("outbox: write item: %w", err)
	}
	if err := o.writeState(o.pendingDir, e); err != nil {
		// The item is durable; Open rebuilds a missing state from it.
		o.cfg.Logf("item %s: state not written (%v); it will be rebuilt", m.ID, err)
	}
	t := &Ticket{Meta: m, done: make(chan Result, 1)}
	o.entries[m.ID] = e
	o.watchers[m.ID] = t.done
	o.signalLocked()
	o.mu.Unlock()
	o.notifyEvicted(evicted, reason)
	return t, nil
}

// capBytesLocked is the effective byte cap: MaxBytes, and at most
// MaxDiskFraction of (the outbox's bytes + the free space).
func (o *Outbox) capBytesLocked() int64 {
	limit := o.cfg.MaxBytes
	if o.cfg.MaxDiskFraction > 0 {
		if free, ok := freeBytes(o.cfg.Dir); ok {
			used := o.usedBytesLocked()
			budget := int64(float64(uint64(used)+free) * o.cfg.MaxDiskFraction) //nolint:gosec // used is non-negative
			if budget < limit {
				limit = budget
			}
		}
	}
	return limit
}

func (o *Outbox) usedBytesLocked() int64 {
	var n int64
	for _, e := range o.entries {
		n += e.size()
	}
	return n
}

// enforceCapsLocked evicts by age, then oldest-first until extra more bytes
// fit under the cap. Dead letters go before pending items; items being
// delivered are skipped. It returns what was evicted for notifyEvicted.
func (o *Outbox) enforceCapsLocked(extra int64) ([]Meta, string) {
	var evicted []Meta
	reasons := map[string]bool{}
	cutoff := o.cfg.now().Add(-o.cfg.MaxAge)
	for _, e := range o.sortedLocked(nil) {
		if e.inflight || !e.meta.CreatedAt.Before(cutoff) {
			continue
		}
		o.evictLocked(e)
		evicted = append(evicted, e.meta)
		reasons[fmt.Sprintf("older than %s", o.cfg.MaxAge)] = true
	}
	limit := o.capBytesLocked()
	used := o.usedBytesLocked()
	if used+extra > limit {
		// Dead letters first, then pending; each oldest first.
		order := o.sortedLocked(func(e *entry) bool { return e.dead != nil })
		order = append(order, o.sortedLocked(func(e *entry) bool { return e.dead == nil })...)
		for _, e := range order {
			if used+extra <= limit {
				break
			}
			if e.inflight {
				continue
			}
			used -= e.size()
			o.evictLocked(e)
			evicted = append(evicted, e.meta)
			reasons[fmt.Sprintf("byte cap %d reached", limit)] = true
		}
	}
	rs := make([]string, 0, len(reasons))
	for r := range reasons {
		rs = append(rs, r)
	}
	sort.Strings(rs)
	return evicted, strings.Join(rs, "; ")
}

func (o *Outbox) evictLocked(e *entry) {
	dir := o.pendingDir
	if e.dead != nil {
		dir = o.deadDir
	}
	_ = removeFiles(filepath.Join(dir, e.meta.ID+itemExt), filepath.Join(dir, e.meta.ID+stateExt), filepath.Join(dir, e.meta.ID+reasonExt))
	delete(o.entries, e.meta.ID)
	o.evicted++
	o.lastEvictAt = o.cfg.now()
	o.finishLocked(e.meta.ID, Result{Evicted: true})
	o.signalLocked()
}

func (o *Outbox) notifyEvicted(evicted []Meta, reason string) {
	if len(evicted) == 0 {
		return
	}
	var oldest time.Time
	for _, m := range evicted {
		if oldest.IsZero() || m.CreatedAt.Before(oldest) {
			oldest = m.CreatedAt
		}
	}
	o.cfg.Logf("WARNING: evicted %d item(s) to stay within the caps (%s); oldest was queued %s. Those results are LOST: give the outbox more space (SENSOR_OUTBOX_MAX_BYTES) or fix the connection to the platform",
		len(evicted), reason, oldest.Format(time.RFC3339))
	if o.cfg.OnEvict != nil {
		o.cfg.OnEvict(evicted, reason)
	}
}

// sortedLocked returns the entries matching keep (nil: all), oldest first.
func (o *Outbox) sortedLocked(keep func(*entry) bool) []*entry {
	out := make([]*entry, 0, len(o.entries))
	for _, e := range o.entries {
		if keep == nil || keep(e) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].meta, out[j].meta
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.Before(b.CreatedAt)
		}
		return a.ID < b.ID
	})
	return out
}

// finishLocked sends an item's final result to its watcher, if any.
func (o *Outbox) finishLocked(id string, r Result) {
	if ch, ok := o.watchers[id]; ok {
		ch <- r
		delete(o.watchers, id)
	}
}

// signalLocked wakes everything waiting for a change.
func (o *Outbox) signalLocked() {
	close(o.changed)
	o.changed = make(chan struct{})
}

// Stats is a snapshot of the outbox, for the heartbeat and metrics.
type Stats struct {
	PendingCount int
	PendingBytes int64
	// OldestPending is the creation time of the oldest pending item (zero
	// when none).
	OldestPending   time.Time
	DeadLetterCount int
	DeadLetterBytes int64
	// Counters since Open.
	Evicted     int64
	Corrupt     int64
	Delivered   int64
	DeadLetters int64
	Attempts    int64
	LastEvictAt time.Time
	// Delivery control.
	AuthPaused   bool
	CircuitOpen  bool
	CircuitUntil time.Time
	CapBytes     int64
}

// OldestAge is the age of the oldest pending item at now.
func (s Stats) OldestAge(now time.Time) time.Duration {
	if s.OldestPending.IsZero() {
		return 0
	}
	return now.Sub(s.OldestPending)
}

// Stats returns a snapshot.
func (o *Outbox) Stats() Stats {
	o.mu.Lock()
	defer o.mu.Unlock()
	var s Stats
	for _, e := range o.entries {
		if e.dead != nil {
			s.DeadLetterCount++
			s.DeadLetterBytes += e.size()
			continue
		}
		s.PendingCount++
		s.PendingBytes += e.size()
		if s.OldestPending.IsZero() || e.meta.CreatedAt.Before(s.OldestPending) {
			s.OldestPending = e.meta.CreatedAt
		}
	}
	now := o.cfg.now()
	s.Evicted, s.Corrupt, s.Delivered, s.DeadLetters, s.Attempts = o.evicted, o.corrupt, o.delivered, o.deadLetters, o.attempts
	s.LastEvictAt = o.lastEvictAt
	s.AuthPaused = o.authPaused
	s.CircuitOpen = now.Before(o.circuitUntil)
	s.CircuitUntil = o.circuitUntil
	s.CapBytes = o.capBytesLocked()
	return s
}

// Pending returns the metadata of the pending items, oldest first.
func (o *Outbox) Pending() []Meta {
	o.mu.Lock()
	defer o.mu.Unlock()
	es := o.sortedLocked(func(e *entry) bool { return e.dead == nil })
	out := make([]Meta, len(es))
	for i, e := range es {
		out[i] = e.meta
	}
	return out
}

// DeadLetters returns the dead letters, oldest first.
func (o *Outbox) DeadLetters() []DeadLetter {
	o.mu.Lock()
	defer o.mu.Unlock()
	es := o.sortedLocked(func(e *entry) bool { return e.dead != nil })
	out := make([]DeadLetter, len(es))
	for i, e := range es {
		out[i] = *e.dead
	}
	return out
}

// DeadLetterForCommand returns a dead letter of a report bound to commandID,
// so a command's result can say its results were refused.
func (o *Outbox) DeadLetterForCommand(commandID string) (DeadLetter, bool) {
	if commandID == "" {
		return DeadLetter{}, false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, e := range o.entries {
		if e.dead != nil && e.meta.CommandID == commandID && e.meta.Kind != KindCommandResult {
			return *e.dead, true
		}
	}
	return DeadLetter{}, false
}

// RequeueDead moves a dead letter back to pending with a fresh attempt count
// (after the operator fixed the cause).
func (o *Outbox) RequeueDead(id string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	e, ok := o.entries[id]
	if !ok || e.dead == nil {
		return fmt.Errorf("outbox: no dead letter %s", id)
	}
	if err := os.Rename(filepath.Join(o.deadDir, id+itemExt), filepath.Join(o.pendingDir, id+itemExt)); err != nil {
		return err
	}
	e.dead = nil
	e.state = State{}
	if err := o.writeState(o.pendingDir, e); err != nil {
		o.cfg.Logf("requeue %s: state not written (%v); it will be rebuilt", id, err)
	}
	_ = removeFiles(filepath.Join(o.deadDir, id+stateExt), filepath.Join(o.deadDir, id+reasonExt))
	_ = syncDir(o.pendingDir)
	o.signalLocked()
	return nil
}

// Close stops accepting items and releases the directory lock. Run returns
// when its context ends; Close does not wait for it.
func (o *Outbox) Close() error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return nil
	}
	o.closed = true
	o.signalLocked()
	o.mu.Unlock()
	if o.unlock != nil {
		o.unlock()
	}
	return nil
}

// Dir returns the outbox directory.
func (o *Outbox) Dir() string { return o.cfg.Dir }

// readPayload loads an item's payload from disk.
func (o *Outbox) readPayload(e *entry) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(o.pendingDir, e.meta.ID+itemExt)) //nolint:gosec // outbox directory
	if err != nil {
		return nil, err
	}
	pt, err := o.seal.open(typeItem, e.meta.ID, data)
	if err != nil {
		return nil, err
	}
	m, payload, err := decodeItem(pt, true)
	if err != nil || m.ID != e.meta.ID {
		return nil, errCorrupt
	}
	return payload, nil
}

// Wait blocks until ctx ends or no pending item is ready to be delivered
// now (everything left is backing off, paused or there is nothing). It is
// what a one-shot run calls before exiting, after Wake.
func (o *Outbox) Wait(ctx context.Context) error {
	for {
		o.mu.Lock()
		busy := false
		now := o.cfg.now()
		for _, e := range o.entries {
			if e.dead != nil {
				continue
			}
			if e.inflight || (o.readyLocked(e, now) && !o.authPaused && !now.Before(o.circuitUntil)) {
				busy = true
				break
			}
		}
		ch := o.changed
		closed := o.closed
		o.mu.Unlock()
		if !busy || closed {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
		case <-time.After(250 * time.Millisecond):
		}
	}
}

var _ = fs.ErrNotExist
