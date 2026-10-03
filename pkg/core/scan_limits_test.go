package core

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCapScanLimit(t *testing.T) {
	cases := []struct {
		requested, own, ceiling, want int
	}{
		{0, 150, 0, 150},      // nothing asked, no ceiling: the scanner's own
		{50, 150, 0, 50},      // a scan may lower it
		{0, 150, 100, 100},    // the ceiling caps the scanner's own value
		{50, 150, 100, 50},    // lower than the ceiling: as asked
		{5000, 150, 100, 100}, // never past the ceiling
		{0, 0, 100, 100},      // nothing set: the ceiling
		{0, 0, 0, 0},          // nothing at all: the tool's default
	}
	for _, c := range cases {
		if got := CapScanLimit(c.requested, c.own, c.ceiling); got != c.want {
			t.Errorf("CapScanLimit(%d, %d, %d) = %d, want %d", c.requested, c.own, c.ceiling, got, c.want)
		}
	}
}

// The executor reads rate_limit, bulk_size and concurrency from the scan
// command's config into the typed options, and fails the command for a
// value it cannot honor rather than dropping it.
func TestExecuteScanReadsScanLimits(t *testing.T) {
	run := func(config map[string]any) (*fakeScanner, error) {
		e := NewDefaultCommandExecutor(nil)
		sc := &fakeScanner{name: "nuclei"}
		e.AddScanner(sc)
		payload, _ := json.Marshal(ScanCommandPayload{Scanner: "nuclei", Target: "https://93.184.215.14", Config: config})
		_, err := e.Execute(context.Background(), &Command{ID: "c1", Type: "scan", Payload: payload})
		return sc, err
	}
	sc, err := run(map[string]any{"rate_limit": 40, "bulk_size": 5, "concurrency": 3})
	if err != nil {
		t.Fatal(err)
	}
	if sc.opts.RateLimit != 40 || sc.opts.BulkSize != 5 || sc.opts.Concurrency != 3 {
		t.Fatalf("opts = %+v, want rate 40, bulk 5, concurrency 3", sc.opts)
	}
	for _, bad := range []map[string]any{
		{"rate_limit": "100000"},
		{"rate_limit": -1},
		{"rate_limit": 0},
		{"bulk_size": 2.5},
		{"concurrency": MaxScanLimit + 1},
	} {
		if sc, err := run(bad); err == nil || sc.calls != 0 {
			t.Errorf("config %v: err = %v, scans = %d; want refused", bad, err, sc.calls)
		}
	}
}
