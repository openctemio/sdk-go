package core

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/openctemio/ctis/politeness"
)

func TestPlanWaves(t *testing.T) {
	cases := []struct {
		name     string
		targets  []string
		maxWaves int
		want     [][]string
	}{
		{"one host stays in one wave",
			[]string{"203.0.113.5", "198.51.100.7", "203.0.113.5:8443", "198.51.100.8"}, 2,
			[][]string{{"203.0.113.5", "203.0.113.5:8443"}, {"198.51.100.7", "198.51.100.8"}}},
		{"fewer hosts than waves",
			[]string{"a.example.com", "https://a.example.com/x"}, 4,
			[][]string{{"a.example.com", "https://a.example.com/x"}}},
		{"maxWaves below one is one wave",
			[]string{"a.example.com", "b.example.com"}, 0,
			[][]string{{"a.example.com", "b.example.com"}}},
		{"balanced by target count",
			[]string{"h1", "h2", "h3", "h4", "h5", "h6", "h7"}, 3,
			[][]string{{"h1", "h4", "h7"}, {"h2", "h5"}, {"h3", "h6"}}},
		{"no targets", nil, 3, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PlanWaves(c.targets, "", c.maxWaves); !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %q want %q", got, c.want)
			}
		})
	}
}

// A chunk shaped like the live case (23 targets over 21 hosts, two hosts
// named twice): every target is in exactly one wave and no two waves share
// a host.
func TestPlanWaves_WholeHosts(t *testing.T) {
	var targets []string
	for i := 1; i <= 21; i++ {
		targets = append(targets, fmt.Sprintf("203.0.113.%d", i))
	}
	targets = append(targets, "203.0.113.3:8443", "203.0.113.9:443")
	waves := PlanWaves(targets, "", 4)
	if len(waves) != 4 {
		t.Fatalf("waves: %d", len(waves))
	}
	var all []string
	for a, w := range waves {
		all = append(all, w...)
		if len(w) < 5 || len(w) > 7 {
			t.Fatalf("wave %d has %d targets", a, len(w))
		}
		for b := a + 1; b < len(waves); b++ {
			ca := politeness.Conflicts(politeness.Keys(w, ""))
			for _, k := range politeness.Keys(waves[b], "") {
				if slices.Contains(ca, k) {
					t.Fatalf("waves %d and %d share %s", a, b, k)
				}
			}
		}
	}
	slices.Sort(all)
	want := slices.Clone(targets)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Fatalf("targets lost or duplicated: %q", all)
	}
}

func TestRunWaves_SettlesEachWaveAsItEnds(t *testing.T) {
	p := NewProgress(0)
	targets := []string{"203.0.113.5", "198.51.100.7", "203.0.113.5:8443"}
	p.SetTargets(targets)
	ctx := WithProgress(context.Background(), p)
	var doneBefore []int
	err := RunWaves(ctx, targets, "", 2, func(_ context.Context, wave []string) error {
		doneBefore = append(doneBefore, p.Snapshot().Done)
		return nil
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The second wave starts after the first wave's 2 targets settled.
	if !slices.Equal(doneBefore, []int{0, 2}) || p.Snapshot().Done != 3 {
		t.Fatalf("done before each wave %v, after %d", doneBefore, p.Snapshot().Done)
	}
}

func TestRunWaves_StopsAtError(t *testing.T) {
	p := NewProgress(0)
	targets := []string{"a.example.com", "b.example.com", "c.example.com"}
	p.SetTargets(targets)
	ctx := WithProgress(context.Background(), p)
	boom := errors.New("boom")
	runs := 0
	err := RunWaves(ctx, targets, "", 3, func(context.Context, []string) error {
		runs++
		return boom
	}, nil)
	if !errors.Is(err, boom) || runs != 1 || p.Snapshot().Done != 1 {
		t.Fatalf("err %v runs %d done %d", err, runs, p.Snapshot().Done)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := RunWaves(cctx, targets, "", 3, func(context.Context, []string) error { return nil }, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
}

func TestRunWaves_OwnDone(t *testing.T) {
	var settled []string
	err := RunWaves(context.Background(), []string{"a.example.com", "b.example.com"}, "", 2,
		func(context.Context, []string) error { return nil },
		func(t string) { settled = append(settled, t) })
	if err != nil || !slices.Equal(settled, []string{"a.example.com", "b.example.com"}) {
		t.Fatalf("err %v settled %q", err, settled)
	}
}
