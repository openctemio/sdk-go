package toolhost

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// HostResolver is a policy that returns the addresses it admitted for a
// host (*core.LocalPolicy does): a confined task's forwarder dials a
// target at those addresses only. Without one, the host is resolved when
// the task starts.
type HostResolver interface {
	AdmittedAddrs(ctx context.Context, host string) ([]netip.Addr, error)
}

// MaxEgressRecords is how many forwarder records an Outcome keeps.
const MaxEgressRecords = 1000

// maxEgressLogLines bounds the refusal lines a task logs.
const maxEgressLogLines = 20

// taskEgress is a confined task's forwarder (api RFC-060): its two unix
// sockets live in a task directory the sandbox hides from every task.
type taskEgress struct {
	fw         *egress.Forwarder
	dir        string
	proxy, dns string
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	once       sync.Once
}

// startEgress starts the forwarder of a task whose backend confines the
// network. A tool with network "none" gets none (no way out at all); a
// backend that does not confine gets none (nil, the task runs as before).
func (h *Host) startEgress(ctx context.Context, be executor.Backend, p *prepared) (*taskEgress, error) {
	if !be.Status().NetworkEnforced || p.m.Permissions.Network == tool.NetNone {
		return nil, nil
	}
	scope := h.taskScope(ctx, p.m, p.task)
	dir, err := executor.NewTaskDir("egress-")
	if err != nil {
		return nil, err
	}
	e := &taskEgress{dir: dir, proxy: filepath.Join(dir, "proxy.sock"), dns: filepath.Join(dir, "dns.sock"),
		fw: egress.New(scope, egress.Limits{Rate: egressRate(p.task.Config, p.m)})}
	pl, err := net.Listen("unix", e.proxy)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("toolhost: forwarder: %w", err)
	}
	dl, err := net.Listen("unix", e.dns)
	if err != nil {
		_ = pl.Close()
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("toolhost: forwarder: %w", err)
	}
	fctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	e.cancel = cancel
	e.wg.Add(2)
	go func() { defer e.wg.Done(); _ = e.fw.Serve(fctx, pl) }()
	go func() { defer e.wg.Done(); _ = e.fw.ServeDNSStream(fctx, dl) }()
	return e, nil
}

// proxyPath and dnsPath are the forwarder's sockets ("" without one).
func (e *taskEgress) proxyPath() string {
	if e == nil {
		return ""
	}
	return e.proxy
}

func (e *taskEgress) dnsPath() string {
	if e == nil {
		return ""
	}
	return e.dns
}

// stop ends the forwarder (once; later calls only read) and returns what
// it recorded.
func (e *taskEgress) stop() ([]egress.Record, int) {
	if e == nil {
		return nil, 0
	}
	e.once.Do(func() {
		e.cancel()
		e.wg.Wait()
		_ = os.RemoveAll(e.dir)
	})
	recs, dropped := e.fw.Records()
	if len(recs) > MaxEgressRecords {
		dropped += len(recs) - MaxEgressRecords
		recs = recs[:MaxEgressRecords]
	}
	return recs, dropped
}

// taskScope is what a task may reach: its admitted targets (names at the
// addresses the policy admitted), the manifest's vendor hosts, or any
// public address for a tool that reaches the internet through the
// sensor's egress.
func (h *Host) taskScope(ctx context.Context, m tool.Manifest, task tool.Task) egress.Scope {
	s := egress.Scope{Names: map[string][]netip.Addr{}}
	switch m.Permissions.Network {
	case tool.NetTargets:
		for _, t := range task.Targets {
			if pfx, err := netip.ParsePrefix(strings.TrimSpace(t.Value)); err == nil {
				s.Prefixes = append(s.Prefixes, pfx.Masked())
				continue
			}
			host := strings.Trim(t.Host(), "[]")
			if host == "" {
				continue
			}
			if a, err := netip.ParseAddr(host); err == nil {
				a = a.Unmap()
				s.Prefixes = append(s.Prefixes, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
			s.Names[host] = h.admittedAddrs(ctx, host)
		}
	case tool.NetVendor:
		s.Vendor = toolrt.VendorHosts(m, task.Config)
	case tool.NetEgressProxy:
		s.AnyPublic = true
	}
	return s
}

func (h *Host) admittedAddrs(ctx context.Context, host string) []netip.Addr {
	if r, ok := h.Policy.(HostResolver); ok && r != nil {
		addrs, _ := r.AdmittedAddrs(ctx, host)
		return addrs
	}
	addrs, _ := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	return addrs
}

// egressRate is the forwarder's connection rate: the tool's own rate
// setting (already capped by the local policy) when it has one, else a
// default high enough for a connect scan.
func egressRate(config json.RawMessage, m tool.Manifest) float64 {
	if m.Safety != nil && m.Safety.RateParam != "" {
		var cfg map[string]any
		if json.Unmarshal(config, &cfg) == nil {
			if v, ok := cfg[m.Safety.RateParam].(float64); ok && v > 0 {
				return v
			}
		}
	}
	return 1000
}

// egressLog turns the forwarder's refusals into the task's log lines (the
// first few; the outcome keeps every record).
func egressLog(recs []egress.Record) []LogLine {
	var out []LogLine
	n := 0
	for _, r := range recs {
		if r.Verdict != egress.Refused {
			continue
		}
		n++
		if len(out) < maxEgressLogLines {
			dest := r.Host
			if r.Port > 0 {
				dest = net.JoinHostPort(r.Host, fmt.Sprint(r.Port))
			}
			out = append(out, LogLine{Level: "warn", Msg: "egress refused " + dest + " (" + r.Protocol + "): " + r.Reason,
				Fields: map[string]any{"egress": "refused", "host": r.Host, "port": r.Port, "protocol": r.Protocol}})
		}
	}
	if n > len(out) {
		out = append(out, LogLine{Level: "warn", Msg: fmt.Sprintf("egress refused %d more destinations", n-len(out))})
	}
	return out
}
