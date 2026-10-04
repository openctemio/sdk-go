package core

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"
)

// cancelPusher answers every plain heartbeat with cancel ids.
type cancelPusher struct {
	doorbellPusher
	ids     []string
	asked   int
	askedMu sync.Mutex
}

func (p *cancelPusher) SendHeartbeatForCancels(context.Context, *SensorStatus) ([]string, error) {
	p.askedMu.Lock()
	p.asked++
	p.askedMu.Unlock()
	return p.ids, nil
}

type cancelRecorder struct {
	mu  sync.Mutex
	ids []string
}

func (r *cancelRecorder) ActiveJobs() int { return 1 }
func (r *cancelRecorder) MaxJobs() int    { return 2 }
func (r *cancelRecorder) CancelCommands(ids ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, ids...)
}

// A sensor without a doorbell still stops what the platform canceled: the
// plain heartbeat reads cancel_command_ids and the poller cancels them.
func TestBaseSensor_NoDoorbellStillHonorsCancels(t *testing.T) {
	p := &cancelPusher{doorbellPusher: doorbellPusher{answer: func(int) *HeartbeatHints { return &HeartbeatHints{} }},
		ids: []string{"c1", "c2"}}
	rec := &cancelRecorder{}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	s.SetLoadReporter(rec)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		rec.mu.Lock()
		n := len(rec.ids)
		rec.mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = s.Stop(context.Background())
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.ids) < 2 || !reflect.DeepEqual(rec.ids[:2], []string{"c1", "c2"}) {
		t.Fatalf("canceled %v, want c1 c2", rec.ids)
	}
	if len(p.times) != 0 {
		t.Fatalf("a sensor without a doorbell sent %d doorbell heartbeats", len(p.times))
	}
}

// Without a load reporter that can cancel, the heartbeat stays exactly the
// plain one.
func TestBaseSensor_NoDoorbellNoCancelerStaysPlain(t *testing.T) {
	p := &cancelPusher{doorbellPusher: doorbellPusher{answer: func(int) *HeartbeatHints { return &HeartbeatHints{} }},
		ids: []string{"c1"}}
	s := NewBaseSensor(&BaseSensorConfig{Name: "t", HeartbeatInterval: time.Hour}, p)
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = s.Stop(context.Background())
	p.askedMu.Lock()
	defer p.askedMu.Unlock()
	if p.asked != 0 || p.plain.Load() < 1 {
		t.Fatalf("asked=%d plain=%d, want the plain heartbeat", p.asked, p.plain.Load())
	}
}
