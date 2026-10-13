package egress

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func askDNS(t *testing.T, f *Forwarder, name string) *dnsmessage.Message {
	t.Helper()
	q := dnsmessage.Message{Header: dnsmessage.Header{ID: 9, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	b, _ := q.Pack()
	out, err := f.AnswerDNS(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(out); err != nil {
		t.Fatal(err)
	}
	return &m
}

// A tool's resolver that appends the host's search domain to a target
// (app.example.com.lan) gets NXDOMAIN, which is what an unknown name is:
// the name is never resolved, and the lookup is not recorded as a refusal
// (a tool may count refusals as host errors). A target that itself ends in
// the search domain still resolves, and any other unknown name is still a
// recorded refusal.
func TestSearchSuffixVariantIsNXDOMAINNotARefusal(t *testing.T) {
	var lookups atomic.Int32
	f := New(Scope{Names: map[string][]netip.Addr{
		"app.example.com": {addr("192.0.2.7")},
		"nas.lan":         {addr("192.0.2.8")},
	}, AnyPublic: true}, Limits{})
	f.SearchDomains = []string{"lan", "corp.example"}
	f.LookupVendor = func(context.Context, string) ([]netip.Addr, error) {
		lookups.Add(1)
		return nil, ErrRefused
	}
	for _, n := range []string{"app.example.com.lan.", "APP.example.com.corp.example.", "missing.example.org.lan."} {
		if m := askDNS(t, f, n); m.RCode != dnsmessage.RCodeNameError || len(m.Answers) != 0 {
			t.Fatalf("%s: %+v, want NXDOMAIN", n, m.Header)
		}
	}
	if n := lookups.Load(); n != 0 {
		t.Fatalf("a search-suffix variant was resolved upstream (%d lookups)", n)
	}
	if r := f.Refusals(); len(r) != 0 {
		t.Fatalf("search-suffix variants recorded as refusals: %+v", r)
	}
	if m := askDNS(t, f, "nas.lan."); len(m.Answers) != 1 {
		t.Fatalf("a target in the search domain: %+v", m)
	}
	// An internal host whose zone is the search domain is not a variant.
	g := New(Scope{Names: map[string][]netip.Addr{
		"host1.corp.example": {addr("192.0.2.9")},
	}}, Limits{})
	g.SearchDomains = []string{"corp.example"}
	if m := askDNS(t, g, "host1.corp.example."); len(m.Answers) != 1 {
		t.Fatalf("an internal target in the search domain's zone: %+v", m)
	}
	if m := askDNS(t, f, "app.example.com."); len(m.Answers) != 1 {
		t.Fatalf("the target: %+v", m)
	}
	// Without the suffix an unknown name is still asked (AnyPublic) and
	// refused as before.
	if m := askDNS(t, f, "other.example."); m.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("unknown name: %+v", m.Header)
	}
	if r := f.Refusals(); len(r) != 1 || r[0].Host != "other.example" {
		t.Fatalf("refusals %+v", r)
	}
}

func TestSearchDomains(t *testing.T) {
	p := filepath.Join(t.TempDir(), "resolv.conf")
	_ = os.WriteFile(p, []byte("# comment\nnameserver 10.0.0.1\nsearch lan Corp.Example.\ndomain home\noptions ndots:1\n"), 0o600)
	if got, want := SearchDomains(p), []string{"lan", "corp.example", "home"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
	if got := SearchDomains(filepath.Join(t.TempDir(), "none")); got != nil {
		t.Fatalf("missing file: %v", got)
	}
}
