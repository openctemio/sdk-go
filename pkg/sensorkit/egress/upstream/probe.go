package upstream

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress"
)

// Testing a proxy (the Test button of the platform's Proxies page). The
// platform never connects to a proxy: it asks sensors to, and each sensor
// tests every endpoint of the pool the command names through the platform's
// echo, a page that answers the address a request came from:
//
//  1. the endpoint's own handshake (TCP, TLS for an https proxy, the
//     credentials) and a tunnel to the echo's address on its port, timed;
//  2. TLS inside the tunnel and one GET of the echo URL, which gives the
//     exit address; the echo's addresses of each family are tried, so the
//     result says whether the proxy carries IPv4, IPv6 or both;
//  3. a tunnel to a second port of the echo host, to tell a proxy that
//     only lets CONNECT to 443 through from one that allows other ports.
//
// The request through the proxy carries a token for this one test in its
// URL and nothing else: never the sensor's key and never a credential. The
// addresses the echo host resolves to are the sensor's own lookup; the
// tunnel is opened by address, as every connection of a pool is.

// Classes of a failed test that are not a proxy class (egress.Class*).
const (
	// ClassEchoFailed: the tunnel came up but the echo did not answer a
	// usable address (a proxy that cuts or alters TLS, or an echo that
	// is down). The proxy may still carry other traffic.
	ClassEchoFailed = "echo_failed"
)

// TestSpec says what a test connects to.
type TestSpec struct {
	// EchoURL is the platform's echo, https://host[:port]/path?token: the
	// token is the only credential-like value on the request.
	EchoURL string
	// AltPort is the second port of the echo host tried to detect a proxy
	// that only allows 443 (0: not tried).
	AltPort int
	// Timeout bounds one endpoint's whole test (0: 20s); one step gets at
	// most Timeout/2.
	Timeout time.Duration
	// RootCAs verify the echo's certificate (nil: the system roots).
	RootCAs *x509.CertPool
	// Resolve looks the echo host up (nil: the system resolver).
	Resolve func(ctx context.Context, host string) ([]netip.Addr, error)

	// allowDenied lets the echo be a loopback address (tests): otherwise
	// an echo address a proxy must never be (Denied: loopback, link-local,
	// metadata, multicast, reserved) is not tunnelled to, so a job cannot
	// aim a tenant's proxy at the proxy's own host or a metadata service.
	allowDenied bool
}

// EndpointResult is the outcome of testing one endpoint. It carries no
// credential and no proxy address beyond the endpoint's id.
type EndpointResult struct {
	EndpointID string `json:"endpoint_id"`
	OK         bool   `json:"ok"`
	// Class is "" when OK, else egress.ClassProxyDown, ClassProxyAuth,
	// ClassTargetUnreachable, ClassTargetRefused or ClassEchoFailed.
	Class string `json:"class,omitempty"`
	// HandshakeMs is the time to a tunnel to the echo (the proxy's own
	// connect, TLS and CONNECT).
	HandshakeMs int `json:"handshake_ms"`
	// ExitIP is the address the echo saw (IPv4 preferred); empty when it
	// could not be learned.
	ExitIP string `json:"exit_ip,omitempty"`
	// Families are the IP families the proxy carried to the echo: "v4",
	// "v6". A family the echo host has no address of is not listed.
	Families []string `json:"families,omitempty"`
	// PortRestricted is true when the proxy refused a tunnel to the echo's
	// second port while it carried 443, false when it carried both, and
	// absent when that was not decided (no second port, or an answer that
	// does not say).
	PortRestricted *bool `json:"port_restricted,omitempty"`
	// Error is one short line, without credentials.
	Error string `json:"error,omitempty"`
}

// maxEchoBody bounds the echo's answer.
const maxEchoBody = 4 << 10

// DialEndpoint opens a tunnel to target through the endpoint with the
// given id and no other: no ranking, no failover, and the endpoint's
// breaker is neither consulted nor opened, so an endpoint that is
// quarantined can be tested. The attempt counts in Report like any other.
// Errors are *egress.UpstreamError.
func (p *Pool) DialEndpoint(ctx context.Context, endpointID string, target netip.AddrPort) (net.Conn, error) {
	i := p.indexOf(endpointID)
	if i < 0 {
		return nil, &egress.UpstreamError{Class: egress.ClassProxyDown, Final: true, Err: fmt.Errorf("upstream: no endpoint %q", endpointID)}
	}
	target = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	e := p.endpoint(i)
	actx, cancel := context.WithTimeout(ctx, p.opts.AttemptTimeout)
	defer cancel()
	start := p.opts.now()
	c, err := p.tunnel(actx, &e, target)
	if err == nil {
		p.observe(i, false, "", false, target.Addr(), p.opts.now().Sub(start), "")
		return c, nil
	}
	class, cause := egress.ClassProxyDown, err
	var ae *attemptError
	if errors.As(err, &ae) {
		class, cause = ae.class, ae.err
	}
	if callerDone(ctx) {
		return nil, &egress.UpstreamError{Class: class, Endpoint: e.ID, Final: true, Err: cause}
	}
	class = p.observe(i, false, class, false, target.Addr(), 0, err.Error())
	return nil, &egress.UpstreamError{Class: class, Endpoint: e.ID, Final: true, Err: cause}
}

func (p *Pool) indexOf(endpointID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range p.cfg.Endpoints {
		if e.ID == endpointID {
			return i
		}
	}
	return -1
}

// Test tests every endpoint of the pool, one after the other, and returns
// one result per endpoint in the pool's order. A cancelled ctx ends the
// test; endpoints not reached are reported as failed with that error.
func (p *Pool) Test(ctx context.Context, spec TestSpec) []EndpointResult {
	echo, err := parseEcho(spec)
	p.mu.Lock()
	ids := make([]string, len(p.cfg.Endpoints))
	for i, e := range p.cfg.Endpoints {
		ids[i] = e.ID
	}
	p.mu.Unlock()
	out := make([]EndpointResult, 0, len(ids))
	for _, id := range ids {
		switch {
		case err != nil:
			out = append(out, EndpointResult{EndpointID: id, Class: ClassEchoFailed, Error: err.Error()})
		case ctx.Err() != nil:
			out = append(out, EndpointResult{EndpointID: id, Class: egress.ClassProxyDown, Error: "test cancelled"})
		default:
			out = append(out, p.testEndpoint(ctx, id, echo))
		}
	}
	return out
}

type echoTarget struct {
	host    string
	port    int
	path    string // path and query, with the token
	altPort int
	spec    TestSpec
}

func parseEcho(spec TestSpec) (echoTarget, error) {
	u, err := url.Parse(spec.EchoURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return echoTarget{}, errors.New("the echo address is not an https URL")
	}
	port := 443
	if ps := u.Port(); ps != "" {
		if _, err := fmt.Sscanf(ps, "%d", &port); err != nil || port < 1 || port > 65535 {
			return echoTarget{}, errors.New("the echo address has no valid port")
		}
	}
	if spec.AltPort < 0 || spec.AltPort > 65535 || spec.AltPort == port {
		return echoTarget{}, errors.New("the echo's second port is not valid")
	}
	return echoTarget{host: u.Hostname(), port: port, path: u.RequestURI(), altPort: spec.AltPort, spec: spec}, nil
}

func (e echoTarget) resolve(ctx context.Context) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(e.host); err == nil {
		if a = a.Unmap(); !e.spec.allowDenied && Denied(a) {
			return nil, nil
		}
		return []netip.Addr{a}, nil
	}
	lookup := e.spec.Resolve
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, e.host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		a = a.Unmap()
		if !e.spec.allowDenied && Denied(a) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func (p *Pool) testEndpoint(ctx context.Context, id string, echo echoTarget) EndpointResult {
	timeout := echo.spec.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res := EndpointResult{EndpointID: id}
	addrs, err := echo.resolve(ctx)
	if err != nil || len(addrs) == 0 {
		res.Class, res.Error = ClassEchoFailed, "the echo host did not resolve to an address a proxy may be asked to reach"
		return res
	}
	var v4, v6 *netip.Addr
	for i := range addrs {
		switch {
		case addrs[i].Is4() && v4 == nil:
			v4 = &addrs[i]
		case addrs[i].Is6() && v6 == nil:
			v6 = &addrs[i]
		}
	}
	stepCtx := func() (context.Context, context.CancelFunc) { return context.WithTimeout(ctx, timeout/2) }
	var firstErr error
	var firstClass string
	var exit4, exit6 string
	for _, c := range []struct {
		fam  string
		addr *netip.Addr
	}{{"v4", v4}, {"v6", v6}} {
		if c.addr == nil {
			continue
		}
		sctx, scancel := stepCtx()
		start := time.Now()
		exit, class, err := p.askEcho(sctx, id, netip.AddrPortFrom(*c.addr, uint16(echo.port)), echo) //nolint:gosec // validated 1..65535
		scancel()
		if err != nil {
			if firstErr == nil {
				firstErr, firstClass = err, class
			}
			continue
		}
		if res.HandshakeMs == 0 {
			res.HandshakeMs = int(time.Since(start).Milliseconds())
		}
		res.Families = append(res.Families, c.fam)
		if c.fam == "v4" {
			exit4 = exit
		} else {
			exit6 = exit
		}
	}
	switch {
	case len(res.Families) == 0:
		res.Class, res.Error = firstClass, sanitizeResultError(firstErr)
		return res
	case exit4 != "":
		res.ExitIP = exit4
	default:
		res.ExitIP = exit6
	}
	res.OK = true
	if echo.altPort > 0 {
		altHost := v4
		if altHost == nil {
			altHost = v6
		}
		sctx, scancel := stepCtx()
		res.PortRestricted = p.altPortRestricted(sctx, id, netip.AddrPortFrom(*altHost, uint16(echo.altPort))) //nolint:gosec // validated 0..65535
		scancel()
	}
	return res
}

// altPortRestricted opens a tunnel to the echo host's second port: true
// when the proxy refuses it (it carried 443), false when it opens, nil when
// the answer does not say (a timeout, or a proxy or host that is down).
func (p *Pool) altPortRestricted(ctx context.Context, id string, target netip.AddrPort) *bool {
	c, err := p.DialEndpoint(ctx, id, target)
	if err == nil {
		_ = c.Close()
		f := false
		return &f
	}
	var ue *egress.UpstreamError
	if errors.As(err, &ue) && ue.Class == egress.ClassTargetRefused {
		t := true
		return &t
	}
	return nil
}

// askEcho opens a tunnel to the echo's address, speaks TLS inside it and
// reads the address the echo saw.
func (p *Pool) askEcho(ctx context.Context, id string, target netip.AddrPort, echo echoTarget) (exit, class string, err error) {
	c, err := p.DialEndpoint(ctx, id, target)
	if err != nil {
		class = egress.ClassProxyDown
		var ue *egress.UpstreamError
		if errors.As(err, &ue) {
			class = ue.Class
		}
		return "", class, err
	}
	defer func() { _ = c.Close() }()
	if d, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(d)
	}
	tc := tls.Client(c, &tls.Config{ServerName: echo.host, MinVersion: tls.VersionTLS12, RootCAs: echo.spec.RootCAs})
	if err := tc.HandshakeContext(ctx); err != nil {
		return "", ClassEchoFailed, fmt.Errorf("tls to the echo through the proxy: %w", err)
	}
	req := "GET " + echo.path + " HTTP/1.1\r\nHost: " + net.JoinHostPort(echo.host, fmt.Sprint(echo.port)) +
		"\r\nAccept: application/json\r\nUser-Agent: openctem-proxy-test\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(tc, req); err != nil {
		return "", ClassEchoFailed, fmt.Errorf("echo request: %w", err)
	}
	br := bufio.NewReader(io.LimitReader(tc, maxEchoBody))
	status, err := br.ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.") || len(status) < 12 || status[9:12] != "200" {
		return "", ClassEchoFailed, errors.New("the echo did not answer 200")
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", ClassEchoFailed, errors.New("the echo's answer is cut")
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}
	body, _ := io.ReadAll(br)
	var out struct {
		Address string `json:"address"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return "", ClassEchoFailed, errors.New("the echo's answer is not the expected JSON")
	}
	a, err := netip.ParseAddr(strings.TrimSpace(out.Address))
	if err != nil || a.Zone() != "" {
		return "", ClassEchoFailed, errors.New("the echo answered no address")
	}
	return a.Unmap().String(), "", nil
}

// sanitizeResultError keeps a result's error to one short line: no URL user
// information, no control characters.
func sanitizeResultError(err error) string {
	if err == nil {
		return ""
	}
	msg := userinfoURL.ReplaceAllString(err.Error(), "${1}")
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > maxLastError {
		msg = strings.ToValidUTF8(msg[:maxLastError], "")
	}
	return msg
}
