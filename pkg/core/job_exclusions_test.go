package core

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// keptAddrs lists every address of a piece list (test sizes only).
func keptAddrs(t *testing.T, pieces []string) map[netip.Addr]bool {
	t.Helper()
	out := map[netip.Addr]bool{}
	for _, s := range pieces {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("piece %q: %v", s, err)
		}
		if p != p.Masked() {
			t.Fatalf("piece %q is not a canonical prefix", s)
		}
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			if out[a] {
				t.Fatalf("address %s is in two pieces", a)
			}
			out[a] = true
		}
	}
	return out
}

// TestRangeCutMatchesBruteForce: on random ranges and exclusions the pieces
// hold exactly the addresses of the range that no exclusion, deny entry or
// built-in deny entry covers.
func TestRangeCutMatchesBruteForce(t *testing.T) {
	r := rand.New(rand.NewSource(88))
	lp := &LocalPolicy{present: true, allowPrivate: false}
	for i := 0; i < 300; i++ {
		bits := 20 + r.Intn(13) // /20 .. /32
		base := netip.AddrFrom4([4]byte{198, 51, byte(r.Intn(256)), byte(r.Intn(256))})
		if r.Intn(4) == 0 {
			// Sometimes a range in private space: those addresses are denied
			// without the private-range switch.
			base = netip.AddrFrom4([4]byte{10, 1, byte(r.Intn(256)), byte(r.Intn(256))})
		}
		p := netip.PrefixFrom(base, bits).Masked()
		var excl []string
		for j := r.Intn(6); j > 0; j-- {
			a := addOffset(p.Addr(), r.Intn(1<<(32-bits)))
			switch r.Intn(3) {
			case 0:
				excl = append(excl, a.String())
			case 1:
				excl = append(excl, netip.PrefixFrom(a, 26+r.Intn(7)).Masked().String())
			default:
				b := a
				for k := r.Intn(40); k > 0 && p.Contains(b.Next()); k-- {
					b = b.Next()
				}
				excl = append(excl, a.String()+"-"+b.String())
			}
		}
		parsed, err := parseJobExclusions(excl)
		if err != nil {
			t.Fatal(err)
		}
		lp.denyNets = nil
		if r.Intn(3) == 0 {
			_, d, _ := net.ParseCIDR(netip.PrefixFrom(addOffset(p.Addr(), r.Intn(1<<(32-bits))), 28).Masked().String())
			lp.denyNets = []*net.IPNet{d}
		}
		c := lp.rangeCutter(parsed)
		kept, _, unchanged := c.cut(p)
		var pieces []string
		for _, k := range kept {
			pieces = append(pieces, k.String())
		}
		got := keptAddrs(t, pieces)
		want := 0
		for a := p.Addr(); p.Contains(a); a = a.Next() {
			allowed := c.skip(a, c.exclusions, c.deny) == ""
			if allowed {
				want++
			}
			if got[a] != allowed {
				t.Fatalf("case %d %s excl %v: address %s kept=%v, want %v", i, p, excl, a, got[a], allowed)
			}
		}
		if len(got) != want {
			t.Fatalf("case %d: %d addresses kept, want %d", i, len(got), want)
		}
		if unchanged != (want == 1<<(32-bits)) {
			t.Fatalf("case %d: unchanged = %v with %d of %d kept", i, unchanged, want, 1<<(32-bits))
		}
	}
}

func TestParseJobExclusions(t *testing.T) {
	got, err := parseJobExclusions([]string{"203.0.113.7", "203.0.113.64/27", "203.0.113.10-203.0.113.12", "::ffff:198.51.100.1", "2001:db8::/126"})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"203.0.113.7/32", "203.0.113.64/27", "203.0.113.10/31", "203.0.113.12/32", "198.51.100.1/32", "2001:db8::/126"}
	var s []string
	for _, p := range got {
		s = append(s, p.String())
	}
	if !slices.Equal(s, want) {
		t.Fatalf("exclusions = %v, want %v", s, want)
	}
	for _, bad := range []string{"", "example.com", "203.0.113.9-203.0.113.1", "203.0.113.1-2001:db8::1", "10.0.0.0/33", strings.Repeat("1", 200)} {
		if _, err := parseJobExclusions([]string{bad}); err == nil {
			t.Errorf("exclusion %q was read", bad)
		}
	}
	if _, err := parseJobExclusions(make([]string, MaxJobExclusions+1)); err == nil {
		t.Error("an over-long exclusion list was read")
	}
}

func TestAdmitCommandTargetsCutsRanges(t *testing.T) {
	ctx := context.Background()
	lp := partialLP(t, partialDNS) // allows 203.0.113.0/24, denies 203.0.113.128/25

	t.Run("a range is cut around the job exclusions and the deny list", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.0/24"}, "exclusions": []string{"203.0.113.7"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if adm.Partial() {
			t.Fatalf("nothing was refused whole: %+v", adm.Refused)
		}
		got := keptAddrs(t, payloadTargets(t, cmd))
		if len(got) != 127 || got[netip.MustParseAddr("203.0.113.7")] || got[netip.MustParseAddr("203.0.113.200")] {
			t.Fatalf("kept %d addresses (%v)", len(got), payloadTargets(t, cmd))
		}
	})

	t.Run("an excluded address target is removed, the rest runs", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.7", "203.0.113.8"}, "exclusions": []string{"203.0.113.7"}})
		adm, err := lp.AdmitCommandTargets(ctx, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if !adm.Partial() || adm.Refused[0].Target != "203.0.113.7" || adm.Refused[0].Rule != RefusalRuleJobExclusions {
			t.Fatalf("refused = %+v", adm.Refused)
		}
		if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"203.0.113.8"}) {
			t.Fatalf("targets = %v", got)
		}
	})

	t.Run("a job whose every target is excluded is refused", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.0/26"}, "exclusions": []string{"203.0.113.0/25"}})
		_, err := lp.AdmitCommandTargets(ctx, cmd)
		var pe *LocalPolicyError
		if !errors.As(err, &pe) || pe.Rule != RefusalRuleJobExclusions {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an unreadable exclusion refuses the job", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"203.0.113.0/26"}, "exclusions": []string{"not-an-address"}})
		_, err := lp.AdmitCommandTargets(ctx, cmd)
		var pe *LocalPolicyError
		if !errors.As(err, &pe) || pe.Rule != "payload" {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("a single target is never run in part", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "target": "203.0.113.0/26", "exclusions": []string{"203.0.113.1"}})
		_, err := lp.AdmitCommandTargets(ctx, cmd)
		var pe *LocalPolicyError
		if !errors.As(err, &pe) || pe.Rule != RefusalRuleJobExclusions {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("names and untouched ranges are left as they are", func(t *testing.T) {
		cmd := cmdWith("c", "scan", map[string]any{"scanner": "nuclei", "targets": []string{"example.com", "203.0.113.0/26"}, "exclusions": []string{"198.51.100.1"}})
		before := string(cmd.Payload)
		if _, err := lp.AdmitCommandTargets(ctx, cmd); err != nil {
			t.Fatal(err)
		}
		if string(cmd.Payload) != before {
			t.Fatalf("payload rewritten: %s", cmd.Payload)
		}
	})
}

// Without a policy file (a legacy install) the job's exclusions and the
// built-in deny list still cut a range.
func TestAdmitCommandTargetsCutsWithoutPolicy(t *testing.T) {
	lp := &LocalPolicy{}
	cmd := cmdWith("c", "scan", map[string]any{"scanner": "naabu", "targets": []string{"198.51.100.0/30", "198.51.100.9"}, "exclusions": []string{"198.51.100.2-198.51.100.9"}})
	adm, err := lp.AdmitCommandTargets(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	if got := payloadTargets(t, cmd); !slices.Equal(got, []string{"198.51.100.0/31"}) {
		t.Fatalf("targets = %v", got)
	}
	if len(adm.Refused) != 1 || adm.Refused[0].Target != "198.51.100.9" {
		t.Fatalf("refused = %+v", adm.Refused)
	}
}

// A range too wide to walk that an exclusion touches is refused whole.
func TestRangeCutWideRange(t *testing.T) {
	excl, _ := parseJobExclusions([]string{"2001:db8::5"})
	c := (&LocalPolicy{present: true}).rangeCutter(excl)
	kept, rule, unchanged := c.cut(netip.MustParsePrefix("2001:db8::/64"))
	if len(kept) != 0 || unchanged || rule != RefusalRuleJobExclusions {
		t.Fatalf("kept %v rule %q unchanged %v", kept, rule, unchanged)
	}
	kept, _, unchanged = c.cut(netip.MustParsePrefix("2001:db8:1::/64"))
	if !unchanged || len(kept) != 1 {
		t.Fatalf("an untouched wide range: kept %v unchanged %v", kept, unchanged)
	}
}

func TestNewScanOptionsCarriesExclusions(t *testing.T) {
	e := &DefaultCommandExecutor{}
	opts, err := e.newScanOptions(&Command{}, "", nil, nil, &ScanCommandPayload{Scanner: "naabu", Exclusions: []string{" 203.0.113.7 ", "203.0.113.64/27"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(opts.ExcludeHosts, []string{"203.0.113.7", "203.0.113.64/27"}) {
		t.Fatalf("exclude hosts = %v", opts.ExcludeHosts)
	}
	if _, err := e.newScanOptions(&Command{}, "", nil, nil, &ScanCommandPayload{Scanner: "naabu", Exclusions: []string{"-x"}}); err == nil {
		t.Fatal("an unreadable exclusion reached the tool options")
	}
}
