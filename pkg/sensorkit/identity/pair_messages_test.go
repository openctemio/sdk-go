package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPairPrintsTheApprovalLink(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.link = "https://ctem.example.test/activate"
	var out bytes.Buffer
	if _, err := Pair(context.Background(), opts(t, srv, &out)); err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	for _, want := range []string{
		"Pair this sensor: open https://ctem.example.test/activate?code=K7QM-4ZTD",
		"Code:        K7QM-4ZTD",
		f.sas.String(),
		"pick this fingerprint",
	} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
}

// A sensor started with the console's code prints that same code and its
// link: one code everywhere.
func TestPairWithACodePrintsTheSameCodeAndItsLink(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.link = "https://ctem.example.test/activate"
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.Code = "r5t7-k2m9"
	o.CodeLabel = "SENSOR_PAIRING_CODE"
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("pair: %v\n%s", err, out.String())
	}
	if f.lastCode != "R5T7K2M9" || !strings.Contains(out.String(), "open https://ctem.example.test/activate?code=R5T7-K2M9") {
		t.Fatalf("code %q, output:\n%s", f.lastCode, out.String())
	}
}

func TestSafeLinkPrintsOnlyPlainHTTPLinks(t *testing.T) {
	for _, bad := range []string{
		"",
		"javascript:alert(1)",
		"ftp://ctem.example.test/activate",
		"https://user:pw@ctem.example.test/activate",
		"https://ctem.example.test/activate?code=K7QM\x1b[2J",
		"https://ctem.example.test/act ivate",
		"https://ctem.example.test/\u202eactivate",
		"/activate?code=K7QM-4ZTD",
		"https://ctem.example.test/" + strings.Repeat("a", maxLinkLen),
	} {
		if got := safeLink(bad); got != "" {
			t.Errorf("safeLink(%q) = %q, want none", bad, got)
		}
	}
	for _, ok := range []string{"https://ctem.example.test/activate?code=K7QM-4ZTD", "http://10.0.0.5:3000/activate"} {
		if safeLink(ok) != ok {
			t.Errorf("safeLink(%q) dropped a valid link", ok)
		}
	}
}

// A platform behind a certificate this host does not trust: one sentence
// with the presented authority's fingerprint, never a silent retry loop.
func TestPairExplainsAnUntrustedCertificate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	t.Cleanup(srv.Close)
	var out bytes.Buffer
	o := PairOptions{BaseURL: srv.URL, Store: NewStore(t.TempDir()), Out: &out,
		HTTPClient: &http.Client{Timeout: 5 * time.Second}, // trusts only the system roots
		Host:       DefaultHostFacts("openctemio-sensor", "0.0.0-test", "dmz-01"),
		sleep:      func(context.Context, time.Duration) error { return nil }}
	_, err := Pair(context.Background(), o)
	var te *UntrustedTLSError
	if !errors.As(err, &te) {
		t.Fatalf("err = %v, want an UntrustedTLSError", err)
	}
	if want := certFingerprint(srv.Certificate()); te.RootSHA256 != want || len(want) != 95 {
		t.Fatalf("fingerprint %q, want %q", te.RootSHA256, want)
	}
	for _, want := range []string{"does not trust", "SENSOR_CA_CERT_FILE", te.RootSHA256} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message lacks %q: %v", want, err)
		}
	}
	if classifyPairError(err, false) != pairWait {
		t.Fatal("an untrusted certificate must wait, not retry in a loop")
	}
}

// The message lists every presented certificate and names the root the top one
// needs, since the platform sends the intermediate and not the root.
func TestUntrustedTLSErrorListsTheChain(t *testing.T) {
	e := &UntrustedTLSError{RootSHA256: "15:BA", Presented: []PresentedCert{
		{Subject: "platform", Issuer: "OpenCTEM Internal CA - 2026 ECC Intermediate", SHA256: "AA:11"},
		{Subject: "OpenCTEM Internal CA - 2026 ECC Intermediate", Issuer: "OpenCTEM Internal CA - 2026 ECC Root", SHA256: "15:BA"},
	}}
	for _, want := range []string{"[1] platform (SHA-256 AA:11)", "[2] OpenCTEM Internal CA - 2026 ECC Intermediate (SHA-256 15:BA)",
		`issued by "OpenCTEM Internal CA - 2026 ECC Root"`, "you need that root", "SENSOR_CA_SHA256"} {
		if !strings.Contains(e.Error(), want) {
			t.Fatalf("message lacks %q:\n%v", want, e)
		}
	}
}
