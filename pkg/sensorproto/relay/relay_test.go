package relay

import (
	"bytes"
	"errors"
	"testing"
)

func TestBatchRoundTrip(t *testing.T) {
	items := []Item{{Sensor: "sensor-1", Envelope: []byte("a")}, {Envelope: bytes.Repeat([]byte{1}, 100)}}
	var buf bytes.Buffer
	if err := WriteBatch(&buf, items); err != nil {
		t.Fatal(err)
	}
	got, err := ReadBatch(bytes.NewReader(buf.Bytes()), 10, 1<<20)
	if err != nil || len(got) != 2 || got[0].Sensor != "sensor-1" || len(got[1].Envelope) != 100 {
		t.Fatalf("%+v %v", got, err)
	}
	for name, r := range map[string]func() error{
		"item cap":  func() error { _, err := ReadBatch(bytes.NewReader(buf.Bytes()), 1, 1<<20); return err },
		"byte cap":  func() error { _, err := ReadBatch(bytes.NewReader(buf.Bytes()), 10, 50); return err },
		"truncated": func() error { _, err := ReadBatch(bytes.NewReader(buf.Bytes()[:buf.Len()-1]), 10, 1<<20); return err },
	} {
		if err := r(); !errors.Is(err, ErrFrame) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestPlatformFraming pins the frame layout the platform's relay writes
// (api pkg/sensorproto/relay): u16 sensor length, sensor, u32 envelope
// length, envelope.
func TestPlatformFraming(t *testing.T) {
	frame := []byte{0, 1, 's', 0, 0, 0, 2, 'e', 'f'}
	got, err := ReadBatch(bytes.NewReader(frame), 4, 1024)
	if err != nil || len(got) != 1 || got[0].Sensor != "s" || string(got[0].Envelope) != "ef" {
		t.Fatalf("%+v %v", got, err)
	}
}

func FuzzReadBatch(f *testing.F) {
	f.Add([]byte{0, 1, 's', 0, 0, 0, 1, 'e'})
	f.Fuzz(func(t *testing.T, b []byte) {
		if items, err := ReadBatch(bytes.NewReader(b), 8, 1<<20); err == nil && len(items) > 8 {
			t.Fatal("item cap ignored")
		}
	})
}
