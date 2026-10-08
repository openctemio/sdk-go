package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// dnsTTL is the TTL of every answer: short, the forwarder holds the truth.
const dnsTTL = 30

// AnswerDNS answers one DNS query (wire format) for a confined task: an
// admitted name gets its pinned addresses, a vendor host its public
// addresses, and every other name NXDOMAIN, so a tool can neither be
// rebound to another address nor carry data out in a lookup. Only A and
// AAAA are answered; other types get an empty answer for admitted names.
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
