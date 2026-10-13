// Package reach tells, per target, whether this sensor got a path to it, and
// summarizes it on the job result so the platform can tell "nothing found"
// from "not reached" and route the next job to a sensor that can reach the
// target (RFC-089 in openctemio/openctem, api/docs/rfcs).
//
// Classify maps an error toward a target to one Class; a Recorder collects
// the outcomes of one job (the command poller puts one in every job's
// context, the guarded dialer and the task forwarder feed it, a tool's
// output parser adds its own) and Recorder.Metadata is the bounded summary
// the job result carries.
package reach

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
)

// Class is the outcome of an attempt to reach one target.
type Class string

// Outcome classes. Reached and PortClosed mean the path works; NoRoute,
// FirewallRefused, Timeout and DNSFailure mean the target was not reached;
// Unknown says nothing about the path (the job was canceled, or the error is
// not a network one).
const (
	// Reached: the target answered (any response, a TLS failure, a reset
	// after the connection opened).
	Reached Class = "reached"
	// PortClosed: the target refused the connection (RST): the path works,
	// the port is closed.
	PortClosed Class = "port_closed"
	// NoRoute: there is no route from this sensor (the local stack or a
	// router on the path says the network or host is unreachable).
	NoRoute Class = "no_route"
	// FirewallRefused: a filter refused this connection (a local firewall,
	// or an administratively prohibited answer on the path).
	FirewallRefused Class = "firewall_refused"
	// Timeout: no answer at all. Ambiguous: filtered, down, or no path.
	Timeout Class = "timeout"
	// DNSFailure: the name does not resolve in this sensor's DNS view.
	DNSFailure Class = "dns_failure"
	// Unknown: not a reach signal.
	Unknown Class = ""
)

// Classes lists the classes a summary counts, best outcome first.
var Classes = []Class{Reached, PortClosed, FirewallRefused, NoRoute, DNSFailure, Timeout}

// Valid reports whether c is one of Classes.
func (c Class) Valid() bool { return c.rank() > 0 }

// PathWorks reports whether c shows a working path to the target.
func (c Class) PathWorks() bool { return c == Reached || c == PortClosed }

// Unreached reports whether c shows the target was not reached.
func (c Class) Unreached() bool { return c.Valid() && !c.PathWorks() }

// rank orders classes for "best outcome wins": a target that answered once
// was reached, whatever else failed. 0 is Unknown.
func (c Class) rank() int {
	for i, k := range Classes {
		if c == k {
			return len(Classes) - i
		}
	}
	return 0
}

// Windows socket error numbers (winsock2.h). syscall.Errno on Windows holds
// these values; they are tested on every platform so the table is checked
// where the tests run.
const (
	wsaeACCES        syscall.Errno = 10013
	wsaeCONNABORTED  syscall.Errno = 10053
	wsaeCONNRESET    syscall.Errno = 10054
	wsaeTIMEDOUT     syscall.Errno = 10060
	wsaeCONNREFUSED  syscall.Errno = 10061
	wsaeNETUNREACH   syscall.Errno = 10051
	wsaeHOSTUNREACH  syscall.Errno = 10065
	wsaeNETDOWN      syscall.Errno = 10050
	wsaeHOSTDOWN     syscall.Errno = 10064
	wsaHOSTNOTFOUND  syscall.Errno = 11001
	wsaNODATA        syscall.Errno = 11004
	wsaTRYAGAIN      syscall.Errno = 11002
	wsaNORECOVERY    syscall.Errno = 11003
	wsaeADDRNOTAVAIL syscall.Errno = 10049
)

// errnoClass maps a socket errno (the names compile on every platform;
// Windows also has the WSA numbers) to its class.
func errnoClass(e syscall.Errno) Class {
	switch e { //nolint:exhaustive // syscall.Errno is not an enum
	case syscall.ECONNREFUSED, wsaeCONNREFUSED:
		return PortClosed
	case syscall.ENETUNREACH, syscall.EHOSTUNREACH, syscall.ENETDOWN, syscall.EHOSTDOWN,
		syscall.EADDRNOTAVAIL, wsaeNETUNREACH, wsaeHOSTUNREACH, wsaeNETDOWN, wsaeHOSTDOWN, wsaeADDRNOTAVAIL:
		// EADDRNOTAVAIL on connect: no local address of the target's family
		// (an IPv6 target on a host without IPv6).
		return NoRoute
	case syscall.EACCES, syscall.EPERM, wsaeACCES:
		// A local filter refused the connect, or (Linux, IPv6) an
		// administratively prohibited answer on the path.
		return FirewallRefused
	case syscall.ETIMEDOUT, wsaeTIMEDOUT:
		return Timeout
	case syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, wsaeCONNRESET, wsaeCONNABORTED:
		return Reached
	case wsaHOSTNOTFOUND, wsaNODATA, wsaTRYAGAIN, wsaNORECOVERY:
		return DNSFailure
	}
	return Unknown
}

// Classify maps an error from an attempt to reach a target to its class. A
// nil error is Reached; a canceled attempt and a non-network error are
// Unknown.
func Classify(err error) Class {
	if err == nil {
		return Reached
	}
	if errors.Is(err, context.Canceled) {
		return Unknown
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return DNSFailure
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		if c := errnoClass(errno); c != Unknown {
			return c
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return Timeout
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || isTLSError(err) {
		return Reached
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return Timeout
	}
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) {
		return Unknown
	}
	return ClassifyText(err.Error())
}

// isTLSError reports whether err is a TLS or certificate failure: the
// target answered.
func isTLSError(err error) bool {
	var rh tls.RecordHeaderError
	var alert tls.AlertError
	var verify *tls.CertificateVerificationError
	var unknownAuth x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	return errors.As(err, &rh) || errors.As(err, &alert) || errors.As(err, &verify) ||
		errors.As(err, &unknownAuth) || errors.As(err, &hostname) || errors.As(err, &invalid)
}

// textClasses map the messages operating systems and tools print for each
// class (lower case), most specific first.
var textClasses = []struct {
	class   Class
	needles []string
}{
	{DNSFailure, []string{
		"no such host", "nxdomain", "servfail", "server misbehaving", "name or service not known",
		"temporary failure in name resolution", "could not resolve", "cannot resolve", "dns lookup failed",
		"no address associated with hostname",
	}},
	{PortClosed, []string{"connection refused", "actively refused", "port unreachable"}},
	{FirewallRefused, []string{
		"administratively prohibited", "admin prohibited", "communication prohibited",
		"operation not permitted", "permission denied", "access permissions",
	}},
	{NoRoute, []string{
		"network is unreachable", "no route to host", "host is unreachable", "host unreachable",
		"network unreachable", "net unreachable", "host is down", "network is down",
		"cannot assign requested address", "unreachable network", "unreachable host",
	}},
	{Timeout, []string{"i/o timeout", "timed out", "timeout", "deadline exceeded", "no response"}},
	{Reached, []string{"connection reset", "broken pipe", "tls:", "x509:", "eof"}},
}

// ClassifyText maps an error message (a tool's per-target failure text, a
// wrapped error that lost its type) to its class; Unknown when it names
// none. Classify uses it as its last resort.
func ClassifyText(msg string) Class {
	lower := strings.ToLower(msg)
	if lower == "" {
		return Unknown
	}
	for _, tc := range textClasses {
		for _, n := range tc.needles {
			if strings.Contains(lower, n) {
				return tc.class
			}
		}
	}
	return Unknown
}

// Port classes group ports so evidence about one service family is not read
// as evidence about another (a firewall that passes 443 may drop 22).
const (
	PortClassWeb   = "web"
	PortClassMgmt  = "mgmt"
	PortClassOther = "other"
	PortClassAny   = "any"
)

// PortClass is the class of port (PortClassAny for 0: no port known).
func PortClass(port int) string {
	switch port {
	case 0:
		return PortClassAny
	case 80, 443, 8000, 8008, 8080, 8443, 8888:
		return PortClassWeb
	case 22, 23, 135, 139, 445, 3389, 5900, 5985, 5986:
		return PortClassMgmt
	}
	return PortClassOther
}
