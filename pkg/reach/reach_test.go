package reach

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
)

// dialErr builds the error net.Dialer returns for a connect to addr that
// failed with errno.
func dialErr(addr string, errno syscall.Errno) error {
	ta, _ := net.ResolveTCPAddr("tcp", addr)
	return &net.OpError{Op: "dial", Net: "tcp", Addr: ta, Err: os.NewSyscallError("connect", errno)}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o deadline reached" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestClassifyErrno(t *testing.T) {
	cases := []struct {
		name  string
		errno syscall.Errno
		want  Class
	}{
		{"ECONNREFUSED", syscall.ECONNREFUSED, PortClosed},
		{"ENETUNREACH", syscall.ENETUNREACH, NoRoute},
		{"EHOSTUNREACH", syscall.EHOSTUNREACH, NoRoute},
		{"ENETDOWN", syscall.ENETDOWN, NoRoute},
		{"EHOSTDOWN", syscall.EHOSTDOWN, NoRoute},
		{"EADDRNOTAVAIL", syscall.EADDRNOTAVAIL, NoRoute},
		{"EACCES", syscall.EACCES, FirewallRefused},
		{"EPERM", syscall.EPERM, FirewallRefused},
		{"ETIMEDOUT", syscall.ETIMEDOUT, Timeout},
		{"ECONNRESET", syscall.ECONNRESET, Reached},
		{"ECONNABORTED", syscall.ECONNABORTED, Reached},
		{"EPIPE", syscall.EPIPE, Reached},
		// Windows socket errors (the numbers syscall.Errno holds there).
		{"WSAECONNREFUSED", 10061, PortClosed},
		{"WSAENETUNREACH", 10051, NoRoute},
		{"WSAEHOSTUNREACH", 10065, NoRoute},
		{"WSAENETDOWN", 10050, NoRoute},
		{"WSAEHOSTDOWN", 10064, NoRoute},
		{"WSAEADDRNOTAVAIL", 10049, NoRoute},
		{"WSAEACCES", 10013, FirewallRefused},
		{"WSAETIMEDOUT", 10060, Timeout},
		{"WSAECONNRESET", 10054, Reached},
		{"WSAECONNABORTED", 10053, Reached},
		{"WSAHOST_NOT_FOUND", 11001, DNSFailure},
		{"WSATRY_AGAIN", 11002, DNSFailure},
		{"WSANO_DATA", 11004, DNSFailure},
	}
	for _, tc := range cases {
		for _, addr := range []string{"192.0.2.10:443", "[2001:db8::10]:443"} {
			t.Run(tc.name+"/"+addr, func(t *testing.T) {
				// The bare errno, the syscall error and the dial error all
				// classify the same.
				for _, err := range []error{
					tc.errno,
					os.NewSyscallError("connect", tc.errno),
					dialErr(addr, tc.errno),
					fmt.Errorf("scan %s: %w", addr, dialErr(addr, tc.errno)),
				} {
					if got := Classify(err); got != tc.want {
						t.Errorf("Classify(%v) = %q, want %q", err, got, tc.want)
					}
				}
			})
		}
	}
}

func TestClassifyOtherErrors(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Class
	}{
		{"nil", nil, Reached},
		{"canceled", context.Canceled, Unknown},
		{"canceled dial", &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}, Unknown},
		{"deadline", context.DeadlineExceeded, Timeout},
		{"os deadline", os.ErrDeadlineExceeded, Timeout},
		{"net timeout", &net.OpError{Op: "dial", Net: "tcp", Err: timeoutErr{}}, Timeout},
		{"dns not found", &net.DNSError{Err: "no such host", Name: "app.example.com", IsNotFound: true}, DNSFailure},
		{"dns timeout", &net.DNSError{Err: "i/o timeout", Name: "app.example.com", IsTimeout: true}, DNSFailure},
		{"dns in op error", &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "server misbehaving", Name: "x.example.com"}}, DNSFailure},
		{"unexpected eof", io.ErrUnexpectedEOF, Reached},
		{"eof", fmt.Errorf("read: %w", io.EOF), Reached},
		{"tls record", tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, Reached},
		{"tls alert", tls.AlertError(40), Reached},
		{"x509 unknown authority", &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}, Reached},
		{"x509 hostname", x509.HostnameError{Host: "app.example.com", Certificate: &x509.Certificate{}}, Reached},
		{"address error", &net.AddrError{Err: "missing port in address", Addr: "192.0.2.1"}, Unknown},
		{"not network", errors.New("parse failed: unexpected token"), Unknown},
		{"text no route", errors.New("dial tcp 198.51.100.7:22: connect: no route to host"), NoRoute},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(tc.err); got != tc.want {
				t.Errorf("Classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestClassifyRealDial classifies what the local stack returns for a
// connection refused on loopback (IPv4 and, when available, IPv6).
func TestClassifyRealDial(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6"} {
		t.Run(network, func(t *testing.T) {
			host := "127.0.0.1"
			if network == "tcp6" {
				host = "::1"
			}
			l, err := net.Listen(network, net.JoinHostPort(host, "0"))
			if err != nil {
				t.Skipf("no %s loopback: %v", network, err)
			}
			addr := l.Addr().String()
			_ = l.Close()
			_, err = net.Dial(network, addr)
			if err == nil {
				t.Skip("port reused")
			}
			if got := Classify(err); got != PortClosed {
				t.Errorf("Classify(%v) = %q, want %q", err, got, PortClosed)
			}
		})
	}
}

func TestClassifyText(t *testing.T) {
	cases := []struct {
		msg  string
		want Class
	}{
		{"", Unknown},
		{"connect: connection refused", PortClosed},
		{"No connection could be made because the target machine actively refused it.", PortClosed},
		{"connect: network is unreachable", NoRoute},
		{"dial tcp [2001:db8::1]:443: connect: no route to host", NoRoute},
		{"host is unreachable", NoRoute},
		{"Destination Host Unreachable", NoRoute},
		{"ICMP communication administratively prohibited", FirewallRefused},
		{"connect: operation not permitted", FirewallRefused},
		{"dial tcp 192.0.2.1:80: i/o timeout", Timeout},
		{"context deadline exceeded", Timeout},
		{"lookup app.example.com: no such host", DNSFailure},
		{"lookup x on 10.0.0.53:53: server misbehaving", DNSFailure},
		{"read: connection reset by peer", Reached},
		{"tls: handshake failure", Reached},
		{"template parse error", Unknown},
	}
	for _, tc := range cases {
		if got := ClassifyText(tc.msg); got != tc.want {
			t.Errorf("ClassifyText(%q) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}

func TestClassPredicates(t *testing.T) {
	for _, c := range Classes {
		if !c.Valid() {
			t.Errorf("%q not valid", c)
		}
		if c.PathWorks() == c.Unreached() {
			t.Errorf("%q: PathWorks and Unreached agree", c)
		}
	}
	if Unknown.Valid() || Unknown.Unreached() || Unknown.PathWorks() {
		t.Error("Unknown must be neither")
	}
	if !(Reached.rank() > PortClosed.rank() && PortClosed.rank() > FirewallRefused.rank() &&
		FirewallRefused.rank() > NoRoute.rank() && NoRoute.rank() > DNSFailure.rank() && DNSFailure.rank() > Timeout.rank()) {
		t.Error("rank order wrong")
	}
}

func TestPortClass(t *testing.T) {
	cases := map[int]string{0: PortClassAny, 443: PortClassWeb, 8080: PortClassWeb, 22: PortClassMgmt,
		3389: PortClassMgmt, 5985: PortClassMgmt, 25: PortClassOther, 65535: PortClassOther}
	for port, want := range cases {
		if got := PortClass(port); got != want {
			t.Errorf("PortClass(%d) = %q, want %q", port, got, want)
		}
	}
}
