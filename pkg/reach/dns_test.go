package reach

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

func TestClassifyDNSSplitsNameGoneFromResolverFailure(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want DNSKind
	}{
		{"nxdomain from the Go resolver", &net.DNSError{Err: "no such host", Name: "gone.example", IsNotFound: true}, NameGone},
		{"no such host without the flag", &net.DNSError{Err: "no such host", Name: "gone.example"}, NameGone},
		{"wrapped nxdomain", fmt.Errorf("dial tcp: %w", &net.DNSError{Err: "no such host", IsNotFound: true}), NameGone},
		{"servfail", &net.DNSError{Err: "server misbehaving", Name: "x.example", Server: "10.0.0.2:53"}, ResolverFailed},
		{"resolver timeout", &net.DNSError{Err: "i/o timeout", Name: "x.example", IsTimeout: true}, ResolverFailed},
		{"temporary", &net.DNSError{Err: "temporary failure", Name: "x.example", IsTemporary: true}, ResolverFailed},
		{"timeout beats not found", &net.DNSError{Err: "no such host", IsNotFound: true, IsTimeout: true}, ResolverFailed},
		{"unknown dns error is not claimed as gone", &net.DNSError{Err: "something odd", Name: "x.example"}, ResolverFailed},
		{"windows host not found", wsaHOSTNOTFOUND, NameGone},
		{"windows no data", wsaNODATA, NameGone},
		{"windows try again", wsaTRYAGAIN, ResolverFailed},
		{"tool text nxdomain", errors.New("dnsx: NXDOMAIN for a.example"), NameGone},
		{"tool text servfail", errors.New("lookup a.example: SERVFAIL"), ResolverFailed},
		{"tool text temporary failure", errors.New("Temporary failure in name resolution"), ResolverFailed},
		{"tool text vague", errors.New("could not resolve host: a.example"), ResolverFailed},
		{"connection refused is not dns", errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), DNSNone},
		{"nil", nil, DNSNone},
	}
	for _, c := range cases {
		if got := ClassifyDNS(c.err); got != c.want {
			t.Errorf("%s: ClassifyDNS = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDNSFailureStaysOneClassOnTheWire(t *testing.T) {
	// The summary's classes are unchanged: older platforms know DNSFailure
	// and nothing else; the refinement rides in the additive reason.
	r := NewRecorder()
	r.RecordErr("gone.example", netipZero, 443, &net.DNSError{Err: "no such host", IsNotFound: true})
	r.RecordErr("sick.example", netipZero, 443, &net.DNSError{Err: "server misbehaving"})
	rep := r.Report()
	if rep.Classes[DNSFailure] != 2 || len(rep.Classes) != 1 {
		t.Fatalf("classes = %v", rep.Classes)
	}
	got := map[string]string{}
	for _, u := range rep.UnreachedList {
		got[u.Target] = u.Reason
	}
	if got["gone.example"] != string(NameGone) || got["sick.example"] != string(ResolverFailed) {
		t.Fatalf("reasons = %v", got)
	}
}

func TestToolReportedDNSFailureDefaultsToResolverFailed(t *testing.T) {
	r := NewRecorder()
	r.Record(Observation{Target: "a.example", Class: DNSFailure})
	r.Record(Observation{Target: "b.example", Class: DNSFailure, Detail: "no such host"})
	c, reason, ok := r.Lookup("a.example")
	if !ok || c != DNSFailure || reason != string(ResolverFailed) {
		t.Fatalf("a: %v %q %v", c, reason, ok)
	}
	if _, reason, _ := r.Lookup("b.example"); reason != string(NameGone) {
		t.Fatalf("b: %q", reason)
	}
}
