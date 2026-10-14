package core

import (
	"encoding/json"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/ctis/politeness"
)

// Per-target release (api research/130): a held command frees each host as
// soon as the targets that need it settle, so the next tool's command on
// that host is admitted before the first command ends.

func metaOf(t *testing.T, payload map[string]any) commandMeta {
	t.Helper()
	raw, _ := json.Marshal(payload)
	return parseCommandMeta(&Command{Payload: raw})
}

func TestLocalQueue_SettleFreesHostsTargetByTarget(t *testing.T) {
	q := newLocalQueue()
	httpx := metaOf(t, map[string]any{"targets": []string{"a.example.com", "b.example.com", "203.0.113.7", "203.0.113.8"}})
	if !q.admit("httpx", commandHosts(httpx), 1, time.Now()) {
		t.Fatal("httpx not admitted")
	}
	q.track("httpx", commandTargets(httpx), httpx.NetworkID)

	nuclei := metaOf(t, map[string]any{"targets": []string{"https://a.example.com/"}})
	if q.admit("nuclei", commandHosts(nuclei), 1, time.Now()) {
		t.Fatal("nuclei admitted while httpx holds its host")
	}
	// A target the job never had, or nothing settled: nothing freed.
	if q.settle("httpx", "evil.example.com") || q.settle("nope", "a.example.com") {
		t.Fatal("freed hosts for a foreign target or command")
	}
	if !q.settle("httpx", "a.example.com") {
		t.Fatal("settling a.example.com freed nothing")
	}
	if q.settle("httpx", "a.example.com") {
		t.Fatal("settling a target twice freed something")
	}
	if !q.admit("nuclei", commandHosts(nuclei), 1, time.Now()) {
		t.Fatal("nuclei not admitted once httpx settled its host")
	}

	// An address goes; its bucket marker stays while the other address of
	// the bucket is pending, so a range scan of the bucket still waits.
	rangeScan := metaOf(t, map[string]any{"targets": []string{"203.0.113.0/24"}})
	q.settle("httpx", "203.0.113.7")
	if q.admit("range", commandHosts(rangeScan), 1, time.Now()) {
		t.Fatal("a range scan was admitted while an address of its bucket is pending")
	}
	q.settle("httpx", "203.0.113.8")
	if !q.admit("range", commandHosts(rangeScan), 1, time.Now()) {
		t.Fatal("range scan not admitted once the bucket's addresses settled")
	}

	// The command ends: only what it still held is freed; the others keep
	// theirs (no count goes below zero).
	q.forget("httpx")
	if q.byHost["a.example.com"] != 1 {
		t.Fatalf("a.example.com held %d times, want 1 (nuclei)", q.byHost["a.example.com"])
	}
	if _, ok := q.byHost["b.example.com"]; ok {
		t.Fatal("b.example.com still held after httpx ended")
	}
	for h, n := range q.byHost {
		if n <= 0 {
			t.Fatalf("host %s count %d", h, n)
		}
	}
}

// The keys the platform sent (payload host_keys) are released the same way:
// the targets produce them.
func TestLocalQueue_SettleReleasesPlatformKeys(t *testing.T) {
	targets := []string{"https://a.example.com/x", "10.0.0.5"}
	const network = "0b9e2c1a-1111-2222-3333-444455556666"
	for _, keyedWith := range []string{"", network} {
		keys := politeness.Keys(targets, keyedWith)
		m := metaOf(t, map[string]any{"targets": targets, "host_keys": keys, "network_id": network})
		q := newLocalQueue()
		q.admit("c", commandHosts(m), 1, time.Now())
		q.track("c", commandTargets(m), m.NetworkID)
		q.settle("c", "https://a.example.com/x")
		q.settle("c", "10.0.0.5")
		if len(q.byHost) != 0 {
			t.Fatalf("keyed with %q: still held %v", keyedWith, q.byHost)
		}
	}
}

// A passive command (empty platform keys) holds nothing, so nothing to free.
func TestLocalQueue_SettleWithoutHosts(t *testing.T) {
	q := newLocalQueue()
	m := metaOf(t, map[string]any{"targets": []string{"a.example.com"}, "host_keys": []string{}})
	q.admit("p", commandHosts(m), 1, time.Now())
	q.track("p", commandTargets(m), "")
	if q.settle("p", "a.example.com") {
		t.Fatal("a command holding no host freed one")
	}
}

// The job's progress drives the release: the executor's target list
// (SetTargets) and each target it reports done. The freed keys are on the
// next heartbeat, and the poller is woken.
func TestLocalQueue_ProgressDrivesRelease(t *testing.T) {
	q := newLocalQueue()
	m := metaOf(t, map[string]any{"targets": []string{"A.example.com", "b.example.com"}})
	q.admit("c", commandHosts(m), 1, time.Now())
	q.track("c", commandTargets(m), "")
	var woken atomic.Int32
	p := NewProgress(0)
	q.setProgress("c", p, func() { woken.Add(1) })
	// The executor runs normalized targets; they produce the same keys.
	p.SetTargets([]string{"a.example.com", "b.example.com"})
	p.TargetDone("a.example.com")
	if woken.Load() != 1 {
		t.Fatalf("woken %d times, want 1", woken.Load())
	}
	snap := q.progress()["c"]
	if snap.Done != 1 || !slices.Equal(snap.ReleasedKeys, []string{"a.example.com"}) {
		t.Fatalf("progress = %+v", snap)
	}
	if !q.admit("next", []string{"a.example.com"}, 1, time.Now()) || q.admit("blocked", []string{"b.example.com"}, 1, time.Now()) {
		t.Fatal("admission does not follow the released hosts")
	}
	// A heartbeat's JSON carries them.
	b, _ := json.Marshal(snap)
	var back map[string]any
	_ = json.Unmarshal(b, &back)
	if _, ok := back["released_keys"]; !ok {
		t.Fatalf("heartbeat progress JSON lacks released_keys: %s", b)
	}
}

// Targets known before the queue observes the progress are taken too.
func TestLocalQueue_ProgressTargetsKnownFirst(t *testing.T) {
	q := newLocalQueue()
	q.admit("c", []string{"a.example.com", "b.example.com"}, 1, time.Now())
	p := NewProgress(0)
	p.SetTargets([]string{"a.example.com", "b.example.com"})
	q.setProgress("c", p, nil)
	p.TargetDone("b.example.com")
	if _, ok := q.byHost["b.example.com"]; ok {
		t.Fatal("b.example.com still held")
	}
}
