package reach

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestRecorderBestOutcomeWins(t *testing.T) {
	r := NewRecorder()
	a := netip.MustParseAddr("192.0.2.10")
	// One host: timeout on 22, closed on 25, answered on 443 -> reached.
	r.Record(Observation{Target: "192.0.2.10", Addr: a, Port: 22, Class: Timeout})
	r.Record(Observation{Target: "192.0.2.10", Addr: a, Port: 25, Class: PortClosed})
	r.Record(Observation{Target: "192.0.2.10", Addr: a, Port: 443, Class: Reached})
	// Another: only timeouts.
	r.Record(Observation{Target: "192.0.2.11", Port: 443, Class: Timeout, Detail: "i/o timeout"})
	r.Record(Observation{Target: "192.0.2.11", Port: 80, Class: Timeout})
	// A v6 host with no route.
	r.RecordErr("2001:db8::5", netip.Addr{}, 22, syscall.ENETUNREACH)
	// A name that does not resolve.
	r.Record(Observation{Target: "gone.example.com", Class: DNSFailure, Detail: "no such host"})
	// Ignored: unknown.
	r.Record(Observation{Target: "198.51.100.1", Class: Unknown})

	rep := r.Report()
	if rep.V != SummaryVersion || rep.Targets != 4 || rep.Reached != 1 || rep.Unreached != 3 {
		t.Fatalf("summary = %+v", rep.Summary)
	}
	wantClasses := map[Class]int{Reached: 1, Timeout: 1, NoRoute: 1, DNSFailure: 1}
	if !reflect.DeepEqual(rep.Classes, wantClasses) {
		t.Errorf("classes = %v, want %v", rep.Classes, wantClasses)
	}
	wantBlocks := []BlockRow{
		{Block: "192.0.2.0/24", PortClass: PortClassMgmt, Timeout: 1},
		{Block: "192.0.2.0/24", PortClass: PortClassOther, PortClosed: 1},
		{Block: "192.0.2.0/24", PortClass: PortClassWeb, Reached: 1, Timeout: 1},
		{Block: "2001:db8::/64", PortClass: PortClassMgmt, NoRoute: 1},
	}
	if !reflect.DeepEqual(rep.Blocks, wantBlocks) || rep.BlocksTotal != 4 {
		t.Errorf("blocks = %+v (%d), want %+v", rep.Blocks, rep.BlocksTotal, wantBlocks)
	}
	wantUnreached := []UnreachedTarget{
		{Target: "192.0.2.11", Class: Timeout, Detail: "i/o timeout"},
		{Target: "2001:db8::5", Class: NoRoute, Detail: "network is unreachable"},
		{Target: "gone.example.com", Class: DNSFailure, Detail: "no such host", Reason: "name_gone"},
	}
	if !reflect.DeepEqual(rep.UnreachedList, wantUnreached) {
		t.Errorf("unreached = %+v, want %+v", rep.UnreachedList, wantUnreached)
	}
}

func TestRecorderMetadataWire(t *testing.T) {
	r := NewRecorder()
	if r.Metadata() != nil {
		t.Fatal("empty recorder must give no metadata")
	}
	var nilRec *Recorder
	nilRec.Record(Observation{Target: "192.0.2.1", Class: Timeout})
	if nilRec.Metadata() != nil || !nilRec.Empty() {
		t.Fatal("nil recorder must be a no-op")
	}
	r.Record(Observation{Target: "192.0.2.1", Port: 443, Class: Reached})
	meta := r.Metadata()
	if _, ok := meta[MetaUnreachedTargets]; ok {
		t.Error("no unreached list when everything was reached")
	}
	r.Record(Observation{Target: "192.0.2.2", Port: 443, Class: NoRoute})
	raw, err := json.Marshal(r.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"reach":{"v":1,"targets":2,"reached":1,"unreached":1,"classes":{"no_route":1,"reached":1},` +
		`"blocks":[{"block":"192.0.2.0/24","port_class":"web","reached":1,"no_route":1}],"blocks_total":1},` +
		`"unreached_targets":[{"target":"192.0.2.2","class":"no_route"}],"unreached_targets_total":1}`
	if string(raw) != want {
		t.Errorf("wire =\n%s\nwant\n%s", raw, want)
	}
}

func TestRecorderBounds(t *testing.T) {
	r := NewRecorder()
	// 600 /24 blocks, each with one unreached address.
	for i := range 600 {
		r.Record(Observation{Target: fmt.Sprintf("10.%d.%d.1", i/256, i%256), Port: 80, Class: Timeout})
	}
	rep := r.Report()
	if len(rep.Blocks) != MaxBlockRows || rep.BlocksTotal != 600 {
		t.Errorf("blocks %d total %d", len(rep.Blocks), rep.BlocksTotal)
	}
	if len(rep.UnreachedList) != MaxUnreachedListed || rep.Unreached != 600 {
		t.Errorf("unreached list %d total %d", len(rep.UnreachedList), rep.Unreached)
	}
	// Deterministic: the same input gives the same JSON.
	a, _ := json.Marshal(r.Metadata())
	b, _ := json.Marshal(r.Metadata())
	if string(a) != string(b) {
		t.Error("metadata not deterministic")
	}
}

func TestRecorderTrackedTargetCap(t *testing.T) {
	r := NewRecorder()
	for i := range MaxTrackedTargets + 10 {
		r.Record(Observation{Target: fmt.Sprintf("host-%d.example.com", i), Class: DNSFailure})
	}
	// Past the cap, outcomes are still counted.
	r.Record(Observation{Target: "late.example.com", Class: Reached})
	rep := r.Report()
	if rep.Targets != MaxTrackedTargets+11 || rep.Reached != 1 {
		t.Errorf("targets %d reached %d", rep.Targets, rep.Reached)
	}
	if len(r.targets) != MaxTrackedTargets {
		t.Errorf("tracked %d", len(r.targets))
	}
}

func TestRecorderCleansUntrustedText(t *testing.T) {
	r := NewRecorder()
	r.Record(Observation{Target: "bad\x1b[31m.example.com\n" + strings.Repeat("a", 1000), Class: DNSFailure,
		Detail: "line1\nline2\x00" + strings.Repeat("é", 200)})
	rep := r.Report()
	got := rep.UnreachedList[0]
	if strings.ContainsAny(got.Target, "\x1b\n") || len(got.Target) > maxTargetLen {
		t.Errorf("target not cleaned: %q", got.Target)
	}
	if strings.ContainsAny(got.Detail, "\n\x00") || len(got.Detail) > maxDetailLen {
		t.Errorf("detail not cleaned: %q", got.Detail)
	}
	if !json.Valid([]byte(`"`+got.Detail+`"`)) || !utf8Valid(got.Detail) {
		t.Errorf("detail cut inside a rune: %q", got.Detail)
	}
}

func utf8Valid(s string) bool { return strings.ToValidUTF8(s, "�") == s }

func TestRecorderIPv4MappedAndURLTargets(t *testing.T) {
	r := NewRecorder()
	r.Record(Observation{Target: "https://app.example.com/login", Addr: netip.MustParseAddr("::ffff:192.0.2.9"), Port: 443, Class: Reached})
	r.Record(Observation{Target: "[2001:db8::9]", Port: 0, Class: Timeout})
	rep := r.Report()
	want := []BlockRow{
		{Block: "192.0.2.0/24", PortClass: PortClassWeb, Reached: 1},
		{Block: "2001:db8::/64", PortClass: PortClassAny, Timeout: 1},
	}
	if !reflect.DeepEqual(rep.Blocks, want) {
		t.Errorf("blocks = %+v", rep.Blocks)
	}
}

func TestRecorderConcurrent(t *testing.T) {
	r := NewRecorder()
	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				r.Record(Observation{Target: fmt.Sprintf("192.0.2.%d", i%250), Port: 80 + g, Class: Timeout})
			}
		}()
	}
	wg.Wait()
	if rep := r.Report(); rep.Targets != 200 {
		t.Errorf("targets = %d", rep.Targets)
	}
}

func TestContextRecorder(t *testing.T) {
	if FromContext(context.Background()) != nil {
		t.Fatal("no recorder expected")
	}
	r := NewRecorder()
	ctx := WithRecorder(context.Background(), r)
	FromContext(ctx).Record(Observation{Target: "192.0.2.1", Class: Reached})
	if r.Empty() {
		t.Error("recorder from context not used")
	}
}
