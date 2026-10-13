package core

// Job exclusions (api RFC-088): a scan job may carry the scope exclusions
// that touch its targets, in the payload's "exclusions" (so the job
// signature covers them). The platform already cuts its range pieces
// around them; the sensor does it again, per address: a range target is
// walked address by address and every address the job excludes, the
// sensor's targets.deny lists or the built-in deny list blocks is left out.
// The rest is handed on as the smallest set of prefixes that covers exactly
// the addresses kept. An address target the job excludes is removed. The
// exclusions also reach the tool (ScanOptions.ExcludeHosts) for tools that
// can skip hosts themselves.

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// RefusalRuleJobExclusions is the rule of a target the job's own
// exclusions remove.
const RefusalRuleJobExclusions = "job_exclusions"

const (
	// MaxJobExclusions bounds the exclusions one job carries.
	MaxJobExclusions = 4096
	// maxJobExclusionLen bounds one exclusion's text.
	maxJobExclusionLen = 128
	// maxRangeWalk is the widest range target the sensor cuts address by
	// address (2^16, the platform's own bound for one range target). A
	// wider range that something blocks is refused whole, as before.
	maxRangeWalk = 1 << 16
)

// parseJobExclusions reads a job's exclusions: addresses, CIDR prefixes and
// "first-last" address ranges, as prefixes. An entry it cannot read
// refuses the job: an exclusion must never be dropped silently.
func parseJobExclusions(list []string) ([]netip.Prefix, error) {
	if len(list) > MaxJobExclusions {
		return nil, refuse("payload", "the job carries %d exclusions, at most %d", len(list), MaxJobExclusions)
	}
	var out []netip.Prefix
	for _, raw := range list {
		s := strings.TrimSpace(raw)
		if s == "" || len(s) > maxJobExclusionLen {
			return nil, refuse("payload", "the job carries an unreadable exclusion %q", truncateBytes(raw, 64))
		}
		ps, err := exclusionPrefixes(s)
		if err != nil {
			return nil, refuse("payload", "the job carries an unreadable exclusion %q: %v", truncateBytes(s, 64), err)
		}
		out = append(out, ps...)
	}
	return out, nil
}

// exclusionPrefixes is one exclusion as prefixes.
func exclusionPrefixes(s string) ([]netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return []netip.Prefix{unmapPrefix(p).Masked()}, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.Unmap().WithZone("")
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
	}
	first, last, ok := strings.Cut(s, "-")
	if !ok {
		return nil, fmt.Errorf("not an address, a prefix or a range")
	}
	a, err1 := netip.ParseAddr(strings.TrimSpace(first))
	b, err2 := netip.ParseAddr(strings.TrimSpace(last))
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("not an address range")
	}
	a, b = a.Unmap().WithZone(""), b.Unmap().WithZone("")
	if a.Is4() != b.Is4() || b.Less(a) {
		return nil, fmt.Errorf("not an address range")
	}
	return rangePrefixes(a, b), nil
}

func unmapPrefix(p netip.Prefix) netip.Prefix {
	if a := p.Addr(); a.Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			bits = 0
		}
		return netip.PrefixFrom(a.Unmap(), bits)
	}
	return p
}

// rangePrefixes is the minimal prefix cover of [a, b] (same family, a <= b).
func rangePrefixes(a, b netip.Addr) []netip.Prefix {
	var out []netip.Prefix
	for {
		// The widest prefix that starts at a and ends at or before b.
		bitsN := a.BitLen()
		for bitsN > 0 {
			p := netip.PrefixFrom(a, bitsN-1)
			if p.Masked().Addr() != a || prefixLast(p).Compare(b) > 0 {
				break
			}
			bitsN--
		}
		p := netip.PrefixFrom(a, bitsN)
		out = append(out, p)
		last := prefixLast(p)
		if last.Compare(b) >= 0 {
			return out
		}
		a = last.Next()
	}
}

// prefixLast is the last address of p.
func prefixLast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// rangeCutter decides, address by address, what of a range target a job
// may scan.
type rangeCutter struct {
	exclusions    []netip.Prefix
	deny          []netip.Prefix
	allowPrivate  bool
	allowLoopback bool
}

func (lp *LocalPolicy) rangeCutter(exclusions []netip.Prefix) *rangeCutter {
	eff := lp
	if !lp.Present() {
		eff = lp.builtinOnly()
	}
	c := &rangeCutter{exclusions: exclusions, allowPrivate: eff.allowPrivate, allowLoopback: eff.allowLoopback || httpsec.AllowLoopback}
	for _, d := range eff.denyNets {
		if p, ok := prefixOfNet(d); ok {
			c.deny = append(c.deny, p)
		}
	}
	return c
}

func prefixOfNet(n *net.IPNet) (netip.Prefix, bool) {
	ones, bitsN := n.Mask.Size()
	ip := n.IP
	if bitsN == 32 {
		ip = ip.To4()
	}
	a, ok := netip.AddrFromSlice(ip)
	if !ok || a.BitLen() != bitsN {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, ones).Masked(), true
}

// skip is why addr is left out ("" when it may be scanned): the job's
// exclusions, then targets.deny, then the built-in deny list.
func (c *rangeCutter) skip(addr netip.Addr, excl, deny []netip.Prefix) string {
	for _, p := range excl {
		if p.Contains(addr) {
			return RefusalRuleJobExclusions
		}
	}
	for _, p := range deny {
		if p.Contains(addr) {
			return "targets.deny"
		}
	}
	ip := net.IP(addr.AsSlice())
	if httpsec.IsIPBlockedWith(ip, c.allowPrivate, c.allowLoopback) {
		if !c.allowPrivate && !httpsec.IsIPBlockedWith(ip, true, c.allowLoopback) {
			return "targets.allow_private"
		}
		return "builtin"
	}
	return ""
}

// overlapping keeps the prefixes of list that overlap p.
func overlapping(list []netip.Prefix, p netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, q := range list {
		if q.Addr().Is4() == p.Addr().Is4() && q.Overlaps(p) {
			out = append(out, q)
		}
	}
	return out
}

// cut walks p and returns the prefixes of the addresses kept, the rule
// that removed the first address left out ("" when nothing was), and
// whether p is unchanged. A range wider than maxRangeWalk that something
// blocks is refused whole (kept empty, rule set).
func (c *rangeCutter) cut(p netip.Prefix) (kept []netip.Prefix, rule string, unchanged bool) {
	p = unmapPrefix(p).Masked()
	excl, deny := overlapping(c.exclusions, p), overlapping(c.deny, p)
	stp := &ScanTargetPolicy{AllowPrivate: c.allowPrivate, AllowLoopback: c.allowLoopback}
	_, n, _ := net.ParseCIDR(p.String())
	if len(excl) == 0 && len(deny) == 0 && stp.checkCIDR(n) == nil {
		return []netip.Prefix{p}, "", true
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits > bits.Len(maxRangeWalk-1) {
		// Too wide to walk: refused whole, with the first reason found.
		switch {
		case len(excl) > 0:
			return nil, RefusalRuleJobExclusions, false
		case len(deny) > 0:
			return nil, "targets.deny", false
		}
		return nil, "builtin", false
	}
	size := 1 << hostBits
	base := p.Addr()
	runStart := -1
	flush := func(end int) {
		if runStart >= 0 {
			kept = append(kept, rangePrefixes(addOffset(base, runStart), addOffset(base, end))...)
			runStart = -1
		}
	}
	for i := 0; i < size; i++ {
		why := c.skip(addOffset(base, i), excl, deny)
		if why == "" {
			if runStart < 0 {
				runStart = i
			}
			continue
		}
		if rule == "" {
			rule = why
		}
		flush(i - 1)
	}
	flush(size - 1)
	return kept, rule, rule == ""
}

// addOffset is base + off for a base aligned to a prefix of at most 2^16
// addresses (off is below that size, so no carry leaves the low 32 bits).
func addOffset(base netip.Addr, off int) netip.Addr {
	b := base.AsSlice()
	low := b[len(b)-4:]
	binary.BigEndian.PutUint32(low, binary.BigEndian.Uint32(low)+uint32(off)) // #nosec G115 -- 0 <= off < 2^16
	a, _ := netip.AddrFromSlice(b)
	return a
}

// jobCut is what cutJobTargets did to a scan job's targets.
type jobCut struct {
	refused []RefusedTarget
	// whole is set when the job's single "target" was cut: the job cannot
	// run on part of it.
	whole error
}

// cutJobTargets applies a scan job's exclusions, the sensor's targets.deny
// and the built-in deny list to its range targets, address by address, and
// removes address targets the job excludes. It rewrites cmd.Payload when it
// changed a target. An unreadable exclusion list refuses the job.
func (lp *LocalPolicy) cutJobTargets(cmd *Command) (*jobCut, error) {
	out := &jobCut{}
	if cmd == nil || cmd.Type != "scan" || len(cmd.Payload) == 0 {
		return out, nil
	}
	var job struct {
		Target     json.RawMessage `json:"target"`
		Targets    []string        `json:"targets"`
		Exclusions []string        `json:"exclusions"`
	}
	if err := json.Unmarshal(cmd.Payload, &job); err != nil {
		// admitJob refuses an unreadable payload with its own reason.
		return out, nil
	}
	excl, err := parseJobExclusions(job.Exclusions)
	if err != nil {
		return out, err
	}
	cutter := lp.rangeCutter(excl)
	// apply returns the replacement of one target: itself, its pieces, or
	// nothing with the refusal.
	apply := func(t string) ([]string, *RefusedTarget) {
		s := strings.TrimSpace(t)
		if p, err := netip.ParsePrefix(s); err == nil {
			kept, rule, unchanged := cutter.cut(p)
			if unchanged {
				return []string{t}, nil
			}
			if len(kept) == 0 {
				rt := refusedTargetOf(t, refuse(rule, "every address of %s is excluded or denied", s))
				return nil, &rt
			}
			pieces := make([]string, len(kept))
			for i, k := range kept {
				pieces[i] = k.String()
			}
			return pieces, nil
		}
		if a, err := netip.ParseAddr(s); err == nil && len(excl) > 0 {
			a = a.Unmap().WithZone("")
			for _, q := range excl {
				if q.Contains(a) {
					rt := refusedTargetOf(t, refuse(RefusalRuleJobExclusions, "%s is excluded from the job's scope", s))
					return nil, &rt
				}
			}
		}
		return []string{t}, nil
	}
	if len(job.Target) > 0 && string(job.Target) != "null" {
		var single string
		if json.Unmarshal(job.Target, &single) == nil && single != "" {
			if got, rt := apply(single); rt != nil || len(got) != 1 || got[0] != single {
				out.whole = refuse(RefusalRuleJobExclusions, "the job's target %s is partly or wholly excluded or denied; it cannot run on part of it", strings.TrimSpace(single))
				return out, out.whole
			}
		}
	}
	changed := false
	kept := make([]string, 0, len(job.Targets))
	for _, t := range job.Targets {
		got, rt := apply(t)
		if rt != nil {
			out.refused = append(out.refused, *rt)
			changed = true
			continue
		}
		if len(got) != 1 || got[0] != t {
			changed = true
		}
		kept = append(kept, got...)
	}
	if !changed {
		return out, nil
	}
	if len(kept) > MaxScanTargets {
		return out, refuse("payload", "cutting the job's ranges around its exclusions left %d targets, at most %d", len(kept), MaxScanTargets)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(cmd.Payload, &fields); err != nil {
		return out, refuse("payload", "the job payload cannot be rewritten")
	}
	raw, err := json.Marshal(kept)
	if err != nil {
		return out, refuse("payload", "the job payload cannot be rewritten")
	}
	fields["targets"] = raw
	payload, err := json.Marshal(fields)
	if err != nil {
		return out, refuse("payload", "the job payload cannot be rewritten")
	}
	cmd.Payload = payload
	return out, nil
}

// jobHasTargetsLeft reports whether a scan payload still names a target.
func jobHasTargetsLeft(cmd *Command) bool {
	var job struct {
		Target  json.RawMessage `json:"target"`
		Targets []string        `json:"targets"`
	}
	if cmd == nil || json.Unmarshal(cmd.Payload, &job) != nil {
		return false
	}
	t := strings.TrimSpace(string(job.Target))
	return len(job.Targets) > 0 || (t != "" && t != "null" && t != `""`)
}
