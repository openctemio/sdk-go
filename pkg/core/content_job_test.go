package core

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openctemio/sdk-go/pkg/jobsig"
)

type contentScanner struct{ recordingScanner }

func (s *contentScanner) TakesJobContent() bool { return true }

type fakeResolver struct {
	mu       sync.Mutex
	reqs     []ContentRequest
	released int
	err      error
}

func (f *fakeResolver) ResolveContent(_ context.Context, req ContentRequest) (*ResolvedContent, func(), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, req)
	if f.err != nil {
		return nil, nil, f.err
	}
	rc := &ResolvedContent{}
	for _, it := range req.Items {
		rc.Slots = append(rc.Slots, ResolvedSlot{Slot: it.Slot, Packs: []ResolvedPack{{Digest: it.Digest, Source: it.Pack, Path: "/cache/" + it.Digest, Files: it.Files}}})
	}
	return rc, func() { f.mu.Lock(); f.released++; f.mu.Unlock() }, nil
}

const (
	dgA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dgB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func platformPack(slot, digest string) JobContent {
	return JobContent{Slot: slot, Kind: "wordlist", Scope: "platform", Pack: "wordlists-m", Digest: digest, Files: []string{"dns/m.txt"}, Signature: []byte(`{"sig":1}`)}
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func inputOf(t testing.TB, slot, purpose, body string) JobInput {
	sum := sha256.Sum256([]byte(body))
	return JobInput{Slot: slot, Purpose: purpose, SHA256: hex.EncodeToString(sum[:]), Lines: strings.Count(body, "\n"), Data: gz(t, []byte(body))}
}

func runContent(t *testing.T, sc Scanner, r ContentResolver, p ScanCommandPayload, verified bool, signed []jobsig.ContentRef, shared bool) error {
	t.Helper()
	e := NewDefaultCommandExecutor(nil)
	e.AddScanner(sc)
	e.SetScanTargetPolicy(newTestPolicy())
	if r != nil {
		e.SetContentResolver(r)
	}
	p.Scanner, p.Target = "rec", "example.com"
	cmd := scanCommand(t, p)
	cmd.jobVerified, cmd.signedContent = verified, signed
	if shared {
		cmd.jobTenant = "tenant-b"
	}
	_, err := e.Execute(context.Background(), cmd)
	return err
}

func isContentRefusal(err error) bool {
	var pe *LocalPolicyError
	return errors.As(err, &pe) && pe.Rule == RefusalRuleJobContent
}

// A job whose signed statement lists exactly its packs gets them resolved,
// held for the scan and released after it; its inline list reaches the scanner
// with the pack in the same slot.
func TestJobContentIsResolvedHeldAndReleased(t *testing.T) {
	sc := &contentScanner{}
	fr := &fakeResolver{}
	in := inputOf(t, "labels", "dns-labels", "staging\nvpn\n")
	p := ScanCommandPayload{Content: []JobContent{platformPack("labels", dgA)}, Inputs: []JobInput{in}}
	if err := runContent(t, sc, fr, p, true, []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}, false); err != nil {
		t.Fatal(err)
	}
	if len(fr.reqs) != 1 || fr.reqs[0].Shared || len(fr.reqs[0].Items) != 1 || fr.released != 1 {
		t.Fatalf("resolver %+v released %d", fr.reqs, fr.released)
	}
	rc := sc.options.Content
	if rc == nil || len(rc.Slots) != 1 || len(rc.Slots[0].Packs) != 1 || len(rc.Slots[0].Inline) != 1 ||
		string(rc.Slots[0].Inline[0].Data) != "staging\nvpn\n" || rc.Slots[0].Inline[0].Purpose != "dns-labels" {
		t.Fatalf("scanner content %+v", rc)
	}
}

// A job mounts only the packs its verified statement lists.
func TestJobContentMustMatchTheSignedStatement(t *testing.T) {
	pack := platformPack("labels", dgA)
	cases := map[string]struct {
		content  []JobContent
		signed   []jobsig.ContentRef
		verified bool
	}{
		"not verified":       {[]JobContent{pack}, nil, false},
		"statement empty":    {[]JobContent{pack}, nil, true},
		"another digest":     {[]JobContent{pack}, []jobsig.ContentRef{{Slot: "labels", Digest: dgB}}, true},
		"another slot":       {[]JobContent{pack}, []jobsig.ContentRef{{Slot: "paths", Digest: dgA}}, true},
		"extra in payload":   {[]JobContent{pack, platformPack("paths", dgB)}, []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}, true},
		"statement has more": {[]JobContent{pack}, []jobsig.ContentRef{{Slot: "labels", Digest: dgA}, {Slot: "paths", Digest: dgB}}, true},
		"statement only":     {nil, []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			fr := &fakeResolver{}
			err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: c.content}, c.verified, c.signed, false)
			if !isContentRefusal(err) || len(fr.reqs) != 0 {
				t.Fatalf("err = %v, resolver calls %d", err, len(fr.reqs))
			}
		})
	}
}

// A shared sensor's job names platform packs only; an organization's pack is
// refused before the cache is asked, and the request is marked shared with the
// signed organization.
func TestSharedJobContent(t *testing.T) {
	signed := []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}
	tenantPack := platformPack("labels", dgA)
	tenantPack.Scope = "tenant"
	fr := &fakeResolver{}
	if err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: []JobContent{tenantPack}}, true, signed, true); !isContentRefusal(err) || len(fr.reqs) != 0 {
		t.Fatalf("tenant pack on a shared sensor: %v (%d resolver calls)", err, len(fr.reqs))
	}
	if err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: []JobContent{platformPack("labels", dgA)}}, true, signed, true); err != nil {
		t.Fatal(err)
	}
	if len(fr.reqs) != 1 || !fr.reqs[0].Shared || fr.reqs[0].Tenant != "tenant-b" {
		t.Fatalf("request %+v", fr.reqs)
	}
}

func TestJobContentNeedsACapableScannerAndACache(t *testing.T) {
	signed := []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}
	p := ScanCommandPayload{Content: []JobContent{platformPack("labels", dgA)}}
	if err := runContent(t, &recordingScanner{}, &fakeResolver{}, p, true, signed, false); !isContentRefusal(err) {
		t.Fatalf("scanner that cannot take content: %v", err)
	}
	if err := runContent(t, &contentScanner{}, nil, p, true, signed, false); !isContentRefusal(err) {
		t.Fatalf("no content cache: %v", err)
	}
	// An inline list alone needs no cache, but still a scanner that takes it.
	in := ScanCommandPayload{Inputs: []JobInput{inputOf(t, "labels", "dns-labels", "a\n")}}
	if err := runContent(t, &contentScanner{}, nil, in, false, nil, false); err != nil {
		t.Fatalf("inline list only: %v", err)
	}
	if err := runContent(t, &recordingScanner{}, nil, in, false, nil, false); !isContentRefusal(err) {
		t.Fatalf("inline list for a scanner that cannot take it: %v", err)
	}
}

func TestDeliveryFailureIsContentUnavailable(t *testing.T) {
	signed := []jobsig.ContentRef{{Slot: "labels", Digest: dgA}}
	fr := &fakeResolver{err: ErrContentUnavailable}
	err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: []JobContent{platformPack("labels", dgA)}}, true, signed, false)
	if !errors.Is(err, ErrContentUnavailable) || isContentRefusal(err) {
		t.Fatalf("err = %v", err)
	}
}

// Inline lists are checked before anything is written: their size, their
// compressed expansion, their hash and their purpose.
func TestInlineListChecks(t *testing.T) {
	good := inputOf(t, "labels", "dns-labels", "a\nb\n")
	bigRaw := strings.Repeat("x\n", MaxJobInputExpanded/2+10)
	bomb := inputOf(t, "labels", "web-paths", bigRaw)
	random := make([]byte, MaxJobInputBytes+1)
	for i := range random {
		random[i] = byte(i*7 + i/251)
	}
	cases := map[string]JobInput{
		"hash":         func() JobInput { x := good; x.SHA256 = strings.Repeat("0", 64); return x }(),
		"purpose":      func() JobInput { x := good; x.Purpose = "passwords"; return x }(),
		"slot":         func() JobInput { x := good; x.Slot = "Bad Slot"; return x }(),
		"not gzip":     func() JobInput { x := good; x.Data = []byte("plain text"); return x }(),
		"empty":        func() JobInput { x := good; x.Data = nil; return x }(),
		"too large":    func() JobInput { x := good; x.Data = random; return x }(),
		"expands past": bomb,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			sc := &contentScanner{}
			err := runContent(t, sc, nil, ScanCommandPayload{Inputs: []JobInput{in}}, false, nil, false)
			if !isContentRefusal(err) || sc.calls != 0 {
				t.Fatalf("err = %v, scanner calls %d", err, sc.calls)
			}
		})
	}
	// The cap on the compressed size is the one the platform is told.
	if MaxJobInputBytes != 256<<10 {
		t.Fatalf("MaxJobInputBytes = %d", MaxJobInputBytes)
	}
}

func TestPackMemberChecks(t *testing.T) {
	signed := func(c JobContent) []jobsig.ContentRef { return []jobsig.ContentRef{{Slot: c.Slot, Digest: c.Digest}} }
	mut := func(f func(*JobContent)) JobContent { c := platformPack("labels", dgA); f(&c); return c }
	for name, c := range map[string]JobContent{
		"bad digest":   mut(func(c *JobContent) { c.Digest = "sha256:xyz" }),
		"bad scope":    mut(func(c *JobContent) { c.Scope = "global" }),
		"bad pack":     mut(func(c *JobContent) { c.Pack = "../x" }),
		"file escapes": mut(func(c *JobContent) { c.Files = []string{"../../etc/passwd"} }),
		"absolute":     mut(func(c *JobContent) { c.Files = []string{"/etc/passwd"} }),
	} {
		t.Run(name, func(t *testing.T) {
			fr := &fakeResolver{}
			err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: []JobContent{c}}, true, signed(c), false)
			if !isContentRefusal(err) || len(fr.reqs) != 0 {
				t.Fatalf("err = %v", err)
			}
		})
	}
	dup := []JobContent{platformPack("labels", dgA), platformPack("labels", dgA)}
	fr := &fakeResolver{}
	if err := runContent(t, &contentScanner{}, fr, ScanCommandPayload{Content: dup}, true,
		[]jobsig.ContentRef{{Slot: "labels", Digest: dgA}, {Slot: "labels", Digest: dgA}}, false); !isContentRefusal(err) {
		t.Fatalf("the same pack twice for one slot: %v", err)
	}
}
