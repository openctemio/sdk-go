// Package relay is the sensor side of the sensor relay's wire contract
// (api docs/rfcs/RFC-116-sensor-relay.md in openctemio/openctem): the
// paths a sensor calls, the ticket header, and the batch framing of the
// envelopes it receives. The platform keeps its own copy of the contract;
// the two are checked against each other by their tests.
//
// Stability: Experimental (docs/STABILITY.md).
package relay

import (
	"encoding/binary"
	"errors"
	"io"
	"regexp"
	"strings"
)

// Paths and headers.
const (
	TicketHeader     = "Openctem-Relay-Ticket"
	BatchContentType = "application/vnd.openctem.relay-batch"
	PathSensorUp     = "/v1/sensor/up"
	PathSensorDown   = "/v1/sensor/down"
	// MaxEnvelope bounds one envelope.
	MaxEnvelope = 16<<20 + 64<<10
)

// ErrFrame is a malformed batch.
var ErrFrame = errors.New("relay: malformed batch")

var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func validID(s string) bool { return idRE.MatchString(s) && !strings.Contains(s, "..") }

// Item is one envelope of a batch (Sensor is empty in a sensor's batch).
type Item struct {
	Sensor   string
	Envelope []byte
}

// WriteBatch frames items: u16 sensor length || sensor || u32 envelope
// length || envelope, repeated.
func WriteBatch(w io.Writer, items []Item) error {
	var hdr [6]byte
	for _, it := range items {
		if len(it.Sensor) > 128 || len(it.Envelope) == 0 || len(it.Envelope) > MaxEnvelope {
			return ErrFrame
		}
		binary.BigEndian.PutUint16(hdr[:2], uint16(len(it.Sensor)))   //nolint:gosec // bounded above
		binary.BigEndian.PutUint32(hdr[2:], uint32(len(it.Envelope))) //nolint:gosec // bounded above
		if _, err := w.Write(hdr[:2]); err != nil {
			return err
		}
		if _, err := io.WriteString(w, it.Sensor); err != nil {
			return err
		}
		if _, err := w.Write(hdr[2:]); err != nil {
			return err
		}
		if _, err := w.Write(it.Envelope); err != nil {
			return err
		}
	}
	return nil
}

// ReadBatch reads a framed batch of at most maxItems items and maxBytes
// envelope bytes.
func ReadBatch(r io.Reader, maxItems int, maxBytes int64) ([]Item, error) {
	var items []Item
	var total int64
	var hdr [4]byte
	for {
		if _, err := io.ReadFull(r, hdr[:2]); err != nil {
			if errors.Is(err, io.EOF) {
				return items, nil
			}
			return nil, ErrFrame
		}
		if len(items) >= maxItems {
			return nil, ErrFrame
		}
		sl := int(binary.BigEndian.Uint16(hdr[:2]))
		if sl > 128 {
			return nil, ErrFrame
		}
		sensor := make([]byte, sl)
		if _, err := io.ReadFull(r, sensor); err != nil {
			return nil, ErrFrame
		}
		if sl > 0 && !validID(string(sensor)) {
			return nil, ErrFrame
		}
		if _, err := io.ReadFull(r, hdr[:4]); err != nil {
			return nil, ErrFrame
		}
		el := int64(binary.BigEndian.Uint32(hdr[:4]))
		if el == 0 || el > MaxEnvelope || total+el > maxBytes {
			return nil, ErrFrame
		}
		total += el
		env := make([]byte, el)
		if _, err := io.ReadFull(r, env); err != nil {
			return nil, ErrFrame
		}
		items = append(items, Item{Sensor: string(sensor), Envelope: env})
	}
}
