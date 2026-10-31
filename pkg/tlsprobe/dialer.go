package tlsprobe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ProxyError is a proxy's refusal of a CONNECT: its status and the first
// line of its body (the task relay writes the upstream error there, which
// reach.ClassifyText reads).
type ProxyError struct {
	Status int
	Body   string
}

func (e *ProxyError) Error() string {
	return fmt.Sprintf("proxy refused the connection (%d): %s", e.Status, e.Body)
}

// maxProxyBody bounds the refusal body read.
const maxProxyBody = 512

// Dialer returns the DialFunc a probe uses: a direct dial when proxyURL is
// empty, else a tunnel through the proxy (http: CONNECT; socks5, socks5h:
// SOCKS5 by name). A confined task passes its egress proxy so the probe
// goes the same way, and through the same scope and rate controls, as the
// task's tools.
func Dialer(proxyURL string) (DialFunc, error) {
	base := &net.Dialer{Timeout: DefaultTimeout, KeepAlive: -1}
	proxyURL = strings.TrimSpace(proxyURL)
	if proxyURL == "" {
		return base.DialContext, nil
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("tlsprobe: proxy is not a URL")
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return connectDialer(base, u), nil
	case "socks5", "socks5h":
		var auth *proxy.Auth
		if u.User != nil {
			pw, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: pw}
		}
		d, err := proxy.SOCKS5("tcp", u.Host, auth, base)
		if err != nil {
			return nil, fmt.Errorf("tlsprobe: socks5 proxy: %w", err)
		}
		cd, ok := d.(proxy.ContextDialer)
		if !ok {
			return nil, fmt.Errorf("tlsprobe: socks5 dialer has no context")
		}
		return cd.DialContext, nil
	}
	return nil, fmt.Errorf("tlsprobe: proxy scheme %q is not http, socks5 or socks5h", u.Scheme)
}

// proxiedConn is a tunnel through an HTTP proxy, with what the proxy sent
// after its answer.
type proxiedConn struct {
	net.Conn
	r io.Reader
}

func (c *proxiedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func connectDialer(base *net.Dialer, u *url.URL) DialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		c, err := base.DialContext(ctx, "tcp", u.Host)
		if err != nil {
			return nil, fmt.Errorf("tlsprobe: proxy: %w", err)
		}
		if dl, ok := ctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		} else {
			_ = c.SetDeadline(time.Now().Add(DefaultTimeout))
		}
		req := &http.Request{
			Method: http.MethodConnect,
			URL:    &url.URL{Opaque: address},
			Host:   address,
			Header: http.Header{},
		}
		if u.User != nil {
			pw, _ := u.User.Password()
			req.SetBasicAuth(u.User.Username(), pw)
			req.Header.Set("Proxy-Authorization", req.Header.Get("Authorization"))
			req.Header.Del("Authorization")
		}
		if err := req.Write(c); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("tlsprobe: proxy: %w", err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, req)
		if err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("tlsprobe: proxy: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxProxyBody))
			_ = resp.Body.Close()
			_ = c.Close()
			line, _, _ := strings.Cut(string(body), "\n")
			return nil, &ProxyError{Status: resp.StatusCode, Body: sanitizeHeader(strings.TrimSpace(line))}
		}
		_ = c.SetDeadline(time.Time{})
		return &proxiedConn{Conn: c, r: br}, nil
	}
}
