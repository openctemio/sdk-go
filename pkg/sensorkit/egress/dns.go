package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsTTL is the TTL of every answer: short, the forwarder holds the truth.
const dnsTTL = 30

// AnswerDNS answers one DNS query (wire format) for a confined task: an
// admitted name gets its pinned addresses, a vendor host its public
// addresses, and every other name NXDOMAIN, so a tool can neither be
// rebound to another address nor carry data out in a lookup. A and AAAA
// are answered from the scope; another type for an admitted name (CNAME,
// MX, TXT, NS, ... a DNS tool's records) is asked of the upstream resolver
// (Upstream) and its answer returned, and without an upstream it is empty.
// Every question is recorded.
func (f *Forwarder) AnswerDNS(ctx context.Context, query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	h, err := p.Start(query)
	if err != nil {
		return nil, err
	}
	q, err := p.Question()
	if err != nil {
		return nil, err
	}
	if h.Response {
		return nil, errors.New("egress: not a query")
	}
	name := normName(q.Name.String())
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired,
		RecursionAvailable: true}, Questions: []dnsmessage.Question{q}}
	rec := Record{Time: time.Now().UTC(), Protocol: "dns", Host: name}
	addrs, rerr := f.resolveName(ctx, name)
	if rerr != nil {
		resp.RCode = dnsmessage.RCodeNameError
		rec.Verdict, rec.Reason = Refused, rerr.Error()
		f.record(rec)
		return resp.Pack()
	}
	rec.Verdict = Allowed
	f.record(rec)
	if q.Type != dnsmessage.TypeA && q.Type != dnsmessage.TypeAAAA && f.Upstream != nil {
		if up, err := f.Upstream(ctx, query); err == nil && sameQuestion(up, h.ID, q) {
			return up, nil
		}
	}
	for _, a := range addrs {
		hdr := dnsmessage.ResourceHeader{Name: q.Name, Class: dnsmessage.ClassINET, TTL: dnsTTL}
		switch {
		case q.Type == dnsmessage.TypeA && a.Is4():
			hdr.Type = dnsmessage.TypeA
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AResource{A: a.As4()}})
		case q.Type == dnsmessage.TypeAAAA && a.Is6():
			hdr.Type = dnsmessage.TypeAAAA
			resp.Answers = append(resp.Answers, dnsmessage.Resource{Header: hdr, Body: &dnsmessage.AAAAResource{AAAA: a.As16()}})
		}
	}
	return resp.Pack()
}

// sameQuestion reports whether an upstream answer answers the query (its
// id and question), so a confused or spoofed answer is never passed on.
func sameQuestion(resp []byte, id uint16, q dnsmessage.Question) bool {
	var p dnsmessage.Parser
	h, err := p.Start(resp)
	if err != nil || !h.Response || h.ID != id {
		return false
	}
	got, err := p.Question()
	return err == nil && got.Type == q.Type && got.Class == q.Class && normName(got.Name.String()) == normName(q.Name.String())
}

// UpstreamDNS returns an Upstream that sends a query to the first resolver
// of resolvConf (the sensor's own /etc/resolv.conf when ""), over UDP, and
// again over TCP when the answer is truncated.
func UpstreamDNS(resolvConf string) func(ctx context.Context, query []byte) ([]byte, error) {
	if resolvConf == "" {
		resolvConf = "/etc/resolv.conf"
	}
	return func(ctx context.Context, query []byte) ([]byte, error) {
		server := "127.0.0.1"
		if b, err := os.ReadFile(resolvConf); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if f := strings.Fields(line); len(f) >= 2 && f[0] == "nameserver" {
					server = f[1]
					break
				}
			}
		}
		addr := net.JoinHostPort(strings.TrimSuffix(strings.SplitN(server, "%", 2)[0], "."), "53")
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", addr)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		if _, err := c.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, 65535)
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		resp := buf[:n]
		var p dnsmessage.Parser
		if h, err := p.Start(resp); err == nil && h.Truncated {
			return tcpDNS(ctx, addr, query)
		}
		return resp, nil
	}
}

func tcpDNS(ctx context.Context, addr string, query []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if len(query) > 65535 {
		return nil, errors.New("egress: query too large")
	}
	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query))) //nolint:gosec // bounded above
	copy(frame[2:], query)
	if _, err := c.Write(frame); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, resp)
	return resp, err
}

// resolveName is Resolve for a name with no port: admitted names and
// vendor hosts only.
func (f *Forwarder) resolveName(ctx context.Context, name string) ([]netip.Addr, error) {
	if _, err := netip.ParseAddr(name); err == nil {
		return nil, ErrRefused
	}
	return f.resolveHost(ctx, name)
}

// ServeDNSStream answers queries on stream connections (RFC 1035 TCP
// framing: a two-byte length before each message), as the relay of a
// confined task sends them, until ctx ends or ln is closed.
func (f *Forwarder) ServeDNSStream(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer c.Close()
			for {
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(l[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				resp, err := f.AnswerDNS(ctx, q)
				if err != nil || len(resp) > 65535 {
					return
				}
				binary.BigEndian.PutUint16(l[:], uint16(len(resp))) //nolint:gosec // bounded above
				if _, err := c.Write(append(l[:], resp...)); err != nil {
					return
				}
			}
		}()
	}
}

// ServeDNS answers queries on pc until ctx ends or pc is closed.
func (f *Forwarder) ServeDNS(ctx context.Context, pc net.PacketConn) error {
	go func() { <-ctx.Done(); _ = pc.Close() }()
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		resp, err := f.AnswerDNS(ctx, buf[:n])
		if err != nil {
			continue
		}
		_, _ = pc.WriteTo(resp, addr)
	}
}
