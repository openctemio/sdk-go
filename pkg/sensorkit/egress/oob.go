package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/internal/absname"
)

// OOBServer is a task's out-of-band interaction server (an interactsh
// compatible server the sensor's operator configured). The tool talks plain
// HTTP to it through the forwarder ("-iserver http://<Host>" with the
// forwarder as its proxy); the forwarder:
//   - answers only absolute-form http requests to Host on port 80, and only
//     the interaction API (POST /register, GET /poll, POST /deregister),
//     with a bounded body;
//   - drops every credential header the tool sent and adds Authorization
//     itself, so the token never reaches the tool, its environment or its
//     command line;
//   - opens a verified TLS connection to Host:Port (system roots, or
//     RootCAs), resolving Host at connect time to public addresses only
//     unless PrivateOK;
//   - never applies the web-scope guard or the path limits to it (it is not
//     a target), and records it as protocol "oob", outside the target tally.
//
// Any other request toward Host (CONNECT, another path, a subdomain, SOCKS)
// is checked as usual, which refuses it unless Host is also a target.
type OOBServer struct {
	// Host is the server's DNS name, which is also the zone of the
	// callback payloads.
	Host string
	// Port is the server's TLS port (0: 443).
	Port int
	// Authorization is the header value the forwarder adds ("": none).
	Authorization string
	// PrivateOK lets Host resolve to private addresses (a server inside the
	// operator's network, which only the sensor's operator can configure).
	// Loopback is private; link-local and metadata addresses stay refused.
	PrivateOK bool
	// RootCAs verify the server's certificate (nil: the system roots).
	RootCAs *x509.CertPool
}

// MaxOOBBody bounds the body of one interaction API request.
const MaxOOBBody = 64 << 10

// ProtocolOOB is the Record protocol of an interaction API request.
const ProtocolOOB = "oob"

// oobRoutes are the interaction API requests the forwarder carries.
var oobRoutes = map[string]string{
	"/register":   http.MethodPost,
	"/poll":       http.MethodGet,
	"/deregister": http.MethodPost,
}

// oobHeaders are the request headers passed on to the server; every other
// one (Authorization and Cookie among them) is dropped.
var oobHeaders = []string{"Accept", "Accept-Encoding", "Content-Type", "User-Agent"}

// isOOB reports whether an absolute-form http request to host:port is for
// the task's interaction server.
func (f *Forwarder) isOOB(host string, port int) bool {
	o := f.scope.OOB
	return o != nil && o.Host != "" && port == 80 && normName(host) == normName(o.Host)
}

// checkOOB checks one interaction API request.
func checkOOB(req *http.Request) error {
	method, ok := oobRoutes[req.URL.Path]
	switch {
	case !ok:
		return fmt.Errorf("%w: %s is not an interaction API path", ErrRefused, req.URL.Path)
	case req.Method != method:
		return fmt.Errorf("%w: %s %s is not an interaction API request", ErrRefused, req.Method, req.URL.Path)
	case method == http.MethodPost && req.URL.RawQuery != "":
		return fmt.Errorf("%w: %s takes no query", ErrRefused, req.URL.Path)
	case req.ContentLength > MaxOOBBody:
		return fmt.Errorf("%w: request body over %d bytes", ErrRefused, MaxOOBBody)
	}
	return nil
}

// serveOOB carries one interaction API request to the task's server.
func (f *Forwarder) serveOOB(ctx context.Context, c net.Conn, req *http.Request, lift func()) {
	o := f.scope.OOB
	port := o.Port
	if port == 0 {
		port = 443
	}
	rec := Record{Time: time.Now().UTC(), Protocol: ProtocolOOB, Host: normName(o.Host), Port: port}
	refuse := func(status int, err error) {
		rec.Verdict, rec.Reason = Refused, err.Error()
		f.record(rec)
		writeHTTPError(c, status, err.Error())
	}
	if err := checkOOB(req); err != nil {
		refuse(http.StatusForbidden, err)
		return
	}
	lift()
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxOOBBody+1))
	if err != nil {
		refuse(http.StatusBadRequest, fmt.Errorf("read the request body: %w", err))
		return
	}
	if len(body) > MaxOOBBody {
		refuse(http.StatusForbidden, fmt.Errorf("%w: request body over %d bytes", ErrRefused, MaxOOBBody))
		return
	}
	out, err := http.NewRequestWithContext(ctx, req.Method, "https://"+rec.Host+req.URL.RequestURI(), bytes.NewReader(body))
	if err != nil {
		refuse(http.StatusBadRequest, err)
		return
	}
	for _, h := range oobHeaders {
		if v := req.Header.Values(h); len(v) > 0 {
			out.Header[h] = v
		}
	}
	if o.Authorization != "" {
		out.Header.Set("Authorization", o.Authorization)
	}
	out.Close = true
	up, addr, err := f.dialOOB(ctx, rec.Host, port)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, ErrRefused) {
			status = http.StatusForbidden
		}
		refuse(status, err)
		return
	}
	defer up.Close()
	rec.Addr = addr
	cw := &countWriter{w: up}
	if err := out.Write(cw); err != nil {
		rec.Verdict, rec.Reason, rec.BytesOut = Allowed, "upstream write failed", cw.n.Load()
		f.record(rec)
		writeHTTPError(c, http.StatusBadGateway, "upstream write failed")
		return
	}
	// The response goes back as it came (the tool reads it as a plain HTTP
	// response); only its status is read here, for the record.
	var head bytes.Buffer
	ur := io.TeeReader(io.LimitReader(up, maxHeaderBytes), &head)
	resp, rerr := http.ReadResponse(bufio.NewReader(ur), out)
	n, _ := c.Write(head.Bytes())
	rest, _ := io.Copy(c, up)
	rec.Verdict, rec.BytesOut, rec.BytesIn = Allowed, cw.n.Load(), int64(n)+rest
	switch {
	case rerr != nil:
		rec.Reason = "no response: " + rerr.Error()
	case resp.StatusCode >= 300:
		rec.Reason = req.Method + " " + req.URL.Path + ": " + strconv.Itoa(resp.StatusCode)
	}
	f.record(rec)
}

// dialOOB resolves host at connect time and opens a verified TLS connection
// to it. It returns the connection and the address dialed.
func (f *Forwarder) dialOOB(ctx context.Context, host string, port int) (net.Conn, string, error) {
	o := f.scope.OOB
	lookup := f.LookupVendor
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", absname.Of(host))
		}
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else if addrs, err = lookup(ctx, host); err != nil {
		return nil, "", fmt.Errorf("egress: resolve %s: %w", host, err)
	}
	var ok []netip.Addr
	for _, a := range addrs {
		a = a.Unmap()
		if alwaysRefused(a) || (!o.PrivateOK && publicOnly(a)) {
			continue
		}
		ok = append(ok, a)
	}
	if len(ok) == 0 {
		return nil, "", fmt.Errorf("%w: %s resolves to no address the interaction server may use", ErrRefused, host)
	}
	cfg := &tls.Config{ServerName: strings.Trim(host, "[]"), RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12}
	var lastErr error
	for _, a := range ok {
		addr := net.JoinHostPort(a.String(), strconv.Itoa(port))
		dctx, cancel := context.WithTimeout(ctx, f.limits.DialTimeout)
		d := &tls.Dialer{Config: cfg}
		c, err := d.DialContext(dctx, "tcp", addr)
		cancel()
		if err == nil {
			return bound(ctx, c, f.limits.UpstreamIdle), addr, nil
		}
		lastErr = err
	}
	return nil, "", fmt.Errorf("egress: interaction server %s: %w", host, lastErr)
}
