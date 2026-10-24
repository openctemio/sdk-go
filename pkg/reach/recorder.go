package reach

import (
	"context"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"unicode"
)

// Result metadata keys of a job's reach outcomes.
const (
	// MetaReach is the job's reach summary (Summary).
	MetaReach = "reach"
	// MetaUnreachedTargets lists targets not reached ([]UnreachedTarget, at
	// most MaxUnreachedListed).
	MetaUnreachedTargets = "unreached_targets"
	// MetaUnreachedTargetsTotal counts every target not reached.
	MetaUnreachedTargetsTotal = "unreached_targets_total"
)

// Bounds of what a job result carries and a recorder keeps.
const (
	// SummaryVersion is the version of Summary's wire format.
	SummaryVersion = 1
	// MaxBlockRows bounds the per-block rows of a summary.
	MaxBlockRows = 512
	// MaxUnreachedListed bounds the unreached targets a result lists.
	MaxUnreachedListed = 100
	// MaxTrackedTargets bounds the targets a recorder keeps apart. Past it,
	// a new target's outcomes are counted without being kept per target
	// (each observation counts once).
	MaxTrackedTargets = 1 << 16
	// maxTargetLen bounds a target's text in a result.
	maxTargetLen = 256
	// maxDetailLen bounds an unreached target's detail.
	maxDetailLen = 160
)

// Observation is one attempt to reach a target.
type Observation struct {
	// Target is the job target as given (a name, an address, a URL).
	Target string
	// Addr is the address dialed (invalid when unknown or the name did
	// not resolve). An address Target is used when Addr is not set.
	Addr netip.Addr
	// Port is the port dialed (0: none or unknown).
	Port int
	// Class is the outcome; Unknown observations are ignored.
	Class Class
	// Detail is a short reason, kept for unreached targets (bounded).
	Detail string
	// Reason refines the class for an unreached target: NameGone or
	// ResolverFailed for DNSFailure (RecordErr sets it). Bounded to a short
	// token.
	Reason string
}

// Summary is the job's reach summary (MetaReach).
type Summary struct {
	V int `json:"v"`
	// Targets counts targets with at least one classified outcome.
	Targets int `json:"targets"`
	// Reached counts targets whose path works (Reached or PortClosed).
	Reached int `json:"reached"`
	// Unreached counts the other targets.
	Unreached int `json:"unreached"`
	// Classes counts targets by their best outcome.
	Classes map[Class]int `json:"classes,omitempty"`
	// Blocks counts addresses per covering block (/24, /64) and port class
	// by best outcome, at most MaxBlockRows rows; BlocksTotal counts all.
	Blocks      []BlockRow `json:"blocks,omitempty"`
	BlocksTotal int        `json:"blocks_total,omitempty"`
}

// BlockRow counts the addresses of one block and port class by outcome.
type BlockRow struct {
	Block           string `json:"block"`
	PortClass       string `json:"port_class"`
	Reached         int    `json:"reached,omitempty"`
	PortClosed      int    `json:"port_closed,omitempty"`
	FirewallRefused int    `json:"firewall_refused,omitempty"`
	NoRoute         int    `json:"no_route,omitempty"`
	Timeout         int    `json:"timeout,omitempty"`
}

func (b *BlockRow) add(c Class) {
	switch c { //nolint:exhaustive // DNS failures and Unknown have no address
	case Reached:
		b.Reached++
	case PortClosed:
		b.PortClosed++
	case FirewallRefused:
		b.FirewallRefused++
	case NoRoute:
		b.NoRoute++
	case Timeout:
		b.Timeout++
	}
}

// UnreachedTarget is one target not reached.
type UnreachedTarget struct {
	Target string `json:"target"`
	Class  Class  `json:"class"`
	Detail string `json:"detail,omitempty"`
	// Reason refines Class (additive; older receivers ignore it): "name_gone"
	// or "resolver_failed" for a DNS failure.
	Reason string `json:"reason,omitempty"`
}

// Report is what a recorder collected.
type Report struct {
	Summary
	// UnreachedList holds at most MaxUnreachedListed targets, ordered by
	// target (Summary.Unreached counts them all).
	UnreachedList []UnreachedTarget
}

// Recorder collects a job's reach outcomes. It is safe for concurrent use;
// a nil *Recorder records nothing.
type Recorder struct {
	mu      sync.Mutex
	targets map[string]*targetState
	// addrs keeps the best outcome per (address, port class).
	addrs map[addrKey]Class
	// overflow counts outcomes of targets past MaxTrackedTargets.
	overflow map[Class]int
	// hosts keeps the best outcome per host (HostOf).
	hosts map[string]*targetState
}

type targetState struct {
	best   Class
	detail string
	reason string
}

type addrKey struct {
	addr      netip.Addr
	portClass string
}

// NewRecorder returns an empty recorder.
func NewRecorder() *Recorder {
	return &Recorder{targets: map[string]*targetState{}, addrs: map[addrKey]Class{}, overflow: map[Class]int{}, hosts: map[string]*targetState{}}
}

// Record adds one observation (an Unknown class is ignored).
func (r *Recorder) Record(o Observation) {
	if r == nil || !o.Class.Valid() {
		return
	}
	if o.Class == DNSFailure && o.Reason == "" {
		// A tool that names a DNS failure without saying which: the safe
		// reading does not claim the name is gone.
		o.Reason = string(ClassifyDNSText(o.Detail))
		if o.Reason == "" {
			o.Reason = string(ResolverFailed)
		}
	}
	target := cleanText(o.Target, maxTargetLen)
	addr := o.Addr
	if !addr.IsValid() {
		addr, _ = netip.ParseAddr(strings.Trim(target, "[]"))
	}
	addr = addr.Unmap()
	if target == "" && addr.IsValid() {
		target = addr.String()
	}
	if target == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if addr.IsValid() && o.Class != DNSFailure {
		k := addrKey{addr: addr, portClass: PortClass(o.Port)}
		if prev, ok := r.addrs[k]; !ok || o.Class.rank() > prev.rank() {
			if ok || len(r.addrs) < MaxTrackedTargets {
				r.addrs[k] = o.Class
			}
		}
	}
	st, ok := r.targets[target]
	if !ok {
		if len(r.targets) >= MaxTrackedTargets {
			r.overflow[o.Class]++
			return
		}
		st = &targetState{}
		r.targets[target] = st
	}
	if o.Class.rank() > st.best.rank() {
		st.best = o.Class
		st.detail = cleanText(o.Detail, maxDetailLen)
		st.reason = cleanToken(o.Reason)
	}
	r.noteHost(target, o)
}

// noteHost keeps the best outcome per host (r.mu held), so a caller that
// holds a URL or an address:port can find what was recorded for the same
// host under another spelling.
func (r *Recorder) noteHost(target string, o Observation) {
	h := HostOf(target)
	if h == "" {
		return
	}
	st, ok := r.hosts[h]
	if !ok {
		if len(r.hosts) >= MaxTrackedTargets {
			return
		}
		st = &targetState{}
		r.hosts[h] = st
	}
	if o.Class.rank() > st.best.rank() {
		st.best = o.Class
		st.detail = cleanText(o.Detail, maxDetailLen)
		st.reason = cleanToken(o.Reason)
	}
}

// Lookup returns the best outcome recorded for target: under exactly that
// text, else for the same host (HostOf). Reason is DNSKind text for a DNS
// failure. ok is false when nothing was recorded.
func (r *Recorder) Lookup(target string) (c Class, reason string, ok bool) {
	if r == nil {
		return Unknown, "", false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if st, found := r.targets[cleanText(target, maxTargetLen)]; found {
		return st.best, st.reason, true
	}
	if st, found := r.hosts[HostOf(target)]; found {
		return st.best, st.reason, true
	}
	return Unknown, "", false
}

// cleanToken keeps a short lower-case identifier (letters, digits, underscore,
// dash) and drops anything else: a reason is data a result carries.
func cleanToken(s string) string {
	if len(s) > 32 {
		return ""
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' && c != '-' {
			return ""
		}
	}
	return s
}

// HostOf returns the lower-case host of a target written as a URL, a
// host:port, a bracketed address or a bare name or address ("" when it holds
// none). It is how outcomes recorded under one spelling of a target are found
// under another.
func HostOf(target string) string {
	t := strings.TrimSpace(target)
	if t == "" {
		return ""
	}
	if i := strings.Index(t, "://"); i >= 0 {
		t = t[i+3:]
		if j := strings.IndexAny(t, "/?#"); j >= 0 {
			t = t[:j]
		}
		if k := strings.LastIndex(t, "@"); k >= 0 {
			t = t[k+1:]
		}
	}
	if strings.HasPrefix(t, "[") {
		if j := strings.Index(t, "]"); j > 0 {
			return strings.ToLower(t[1:j])
		}
		return ""
	}
	if strings.Count(t, ":") == 1 {
		t, _, _ = strings.Cut(t, ":")
	}
	if j := strings.IndexAny(t, "/?#"); j >= 0 {
		t = t[:j]
	}
	return strings.ToLower(strings.TrimSuffix(t, "."))
}

// RecordErr classifies err and records it; it returns the class.
func (r *Recorder) RecordErr(target string, addr netip.Addr, port int, err error) Class {
	c := Classify(err)
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	reason := ""
	if c == DNSFailure {
		reason = string(ClassifyDNS(err))
	}
	r.Record(Observation{Target: target, Addr: addr, Port: port, Class: c, Detail: detail, Reason: reason})
	return c
}

// Empty reports whether nothing was recorded.
func (r *Recorder) Empty() bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.targets) == 0 && len(r.overflow) == 0
}

// Report returns what was recorded, bounded and in a stable order.
func (r *Recorder) Report() Report {
	rep := Report{Summary: Summary{V: SummaryVersion}}
	if r == nil {
		return rep
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	classes := map[Class]int{}
	var unreached []UnreachedTarget
	for t, st := range r.targets {
		classes[st.best]++
		if st.best.Unreached() {
			unreached = append(unreached, UnreachedTarget{Target: t, Class: st.best, Detail: st.detail, Reason: st.reason})
		}
	}
	for c, n := range r.overflow {
		classes[c] += n
	}
	for c, n := range classes {
		rep.Targets += n
		if c.PathWorks() {
			rep.Reached += n
		} else {
			rep.Unreached += n
		}
	}
	if len(classes) > 0 {
		rep.Classes = classes
	}
	sort.Slice(unreached, func(i, j int) bool { return unreached[i].Target < unreached[j].Target })
	if len(unreached) > MaxUnreachedListed {
		unreached = unreached[:MaxUnreachedListed]
	}
	rep.UnreachedList = unreached
	rep.Blocks, rep.BlocksTotal = r.blocks()
	return rep
}

// blocks folds the per-address outcomes into block rows (r.mu held).
func (r *Recorder) blocks() ([]BlockRow, int) {
	type blockKey struct {
		block     netip.Prefix
		portClass string
	}
	rows := map[blockKey]*BlockRow{}
	for k, c := range r.addrs {
		bits := 24
		if k.addr.Is6() {
			bits = 64
		}
		p, err := k.addr.Prefix(bits)
		if err != nil {
			continue
		}
		bk := blockKey{block: p, portClass: k.portClass}
		row := rows[bk]
		if row == nil {
			row = &BlockRow{Block: p.String(), PortClass: k.portClass}
			rows[bk] = row
		}
		row.add(c)
	}
	keys := make([]blockKey, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c := keys[i].block.Addr().Compare(keys[j].block.Addr()); c != 0 {
			return c < 0
		}
		if keys[i].block.Bits() != keys[j].block.Bits() {
			return keys[i].block.Bits() < keys[j].block.Bits()
		}
		return keys[i].portClass < keys[j].portClass
	})
	total := len(keys)
	if len(keys) > MaxBlockRows {
		keys = keys[:MaxBlockRows]
	}
	out := make([]BlockRow, 0, len(keys))
	for _, k := range keys {
		out = append(out, *rows[k])
	}
	if total == 0 {
		return nil, 0
	}
	return out, total
}

// Metadata returns the job result metadata for what was recorded (nil when
// nothing was).
func (r *Recorder) Metadata() map[string]any {
	if r.Empty() {
		return nil
	}
	rep := r.Report()
	meta := map[string]any{MetaReach: rep.Summary}
	if rep.Unreached > 0 {
		meta[MetaUnreachedTargets] = rep.UnreachedList
		meta[MetaUnreachedTargetsTotal] = rep.Unreached
	}
	return meta
}

// cleanText bounds s and drops control characters (it ends up in a result
// the platform shows).
func cleanText(s string, n int) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s))
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

type ctxKey struct{}

// WithRecorder returns ctx carrying r: everything that dials a job's
// targets under ctx records into r.
func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// FromContext returns the recorder ctx carries (nil: none; recording into
// nil is a no-op).
func FromContext(ctx context.Context) *Recorder {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(ctxKey{}).(*Recorder)
	return r
}
