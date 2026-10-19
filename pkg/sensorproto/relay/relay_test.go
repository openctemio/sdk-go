package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
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

// TestBatchVector pins the wire framing against the file shared with the
// sdk-go copy of this package; both sides keep testdata/vector-batch-v1.json
// byte-identical.
func TestBatchVector(t *testing.T) {
	raw, err := os.ReadFile("testdata/vector-batch-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Items []struct {
			Sensor      string `json:"sensor"`
			EnvelopeHex string `json:"envelope_hex"`
		} `json:"items"`
		FramedHex string            `json:"framed_hex"`
		Invalid   map[string]string `json:"invalid_frames_hex"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var items []Item
	for _, it := range v.Items {
		env, err := hex.DecodeString(it.EnvelopeHex)
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, Item{Sensor: it.Sensor, Envelope: env})
	}
	var buf bytes.Buffer
	if err := WriteBatch(&buf, items); err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(buf.Bytes()); got != v.FramedHex {
		t.Fatalf("framing drifted from the vector:\n got %s\nwant %s", got, v.FramedHex)
	}
	framed, _ := hex.DecodeString(v.FramedHex)
	got, err := ReadBatch(bytes.NewReader(framed), 10, 1<<20)
	if err != nil || len(got) != len(items) {
		t.Fatalf("read vector: %v %v", got, err)
	}
	for i := range items {
		if got[i].Sensor != items[i].Sensor || !bytes.Equal(got[i].Envelope, items[i].Envelope) {
			t.Fatalf("item %d differs: %+v", i, got[i])
		}
	}
	for name, h := range v.Invalid {
		b, _ := hex.DecodeString(h)
		if _, err := ReadBatch(bytes.NewReader(b), 10, 1<<20); !errors.Is(err, ErrFrame) {
			t.Errorf("invalid frame %s accepted: %v", name, err)
		}
	}
}
