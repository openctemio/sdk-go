package core

import (
	"net"
	"net/netip"

	"github.com/openctemio/sdk-go/pkg/netctx"
)

// NetworkScope is what the sensor's network report may name (netctx.Scope):
// the policy's targets.allow ranges (when the policy has an allow list),
// its targets.deny ranges and whether private targets are allowed. A
// sensor that requires a policy and has none may name no prefix at all.
// The report is never wider than what this sensor would scan.
func (lp *LocalPolicy) NetworkScope() netctx.Scope {
	if lp.failsClosed() {
		return netctx.Scope{Set: true, NoPrivate: true}
	}
	if lp == nil || !lp.present {
		return netctx.Scope{NoPrivate: !DefaultScanTargetPolicy().AllowPrivate}
	}
	s := netctx.Scope{Set: lp.targetsAllowSet, NoPrivate: !lp.allowPrivate}
	s.Allow = ipNetPrefixes(lp.allowNets)
	s.Deny = ipNetPrefixes(lp.denyNets)
	return s
}

func ipNetPrefixes(ns []*net.IPNet) []netip.Prefix {
	var out []netip.Prefix
	for _, n := range ns {
		a, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		ones, bits := n.Mask.Size()
		if bits == 0 {
			continue
		}
		a = a.Unmap()
		if a.Is4() && bits == 128 {
			ones -= 96
		}
		out = append(out, netip.PrefixFrom(a, ones).Masked())
	}
	return out
}
