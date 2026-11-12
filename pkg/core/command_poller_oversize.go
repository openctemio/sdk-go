package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// An oversized poll answer. The platform's answer to the commands poll is
// read up to 10 MiB. One command with a large payload can push the answer
// over that, and since the platform holds (claims) what it returned, the
// same command comes back at every poll: without a reaction the sensor would
// poll forever and never start anything. The poller asks for fewer commands
// each time (half, down to one) and, when a single command is still too
// large, fails that command by its id, which the client keeps from the first
// bytes of the answer. Nothing is ever run from a truncated answer.

const (
	// oversizeLogEvery is the most often the same oversized state is logged.
	oversizeLogEvery = 10 * time.Minute
	// oversizeReason is what the platform shows for the failed command.
	oversizeReason = "the command's payload is larger than the 10 MiB the sensor accepts"
)

// oversizeState is the poller's memory of oversized poll answers.
type oversizeState struct {
	mu sync.Mutex
	// capAsk limits the commands a poll asks for; 0: no limit.
	capAsk int
	// lastLog and lastLogCap say when and for which limit it was last logged.
	lastLog    time.Time
	lastLogCap int
}

// limit applies the cap to what the poll would ask for.
func (s *oversizeState) limit(ask int) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.capAsk > 0 {
		return min(ask, s.capAsk)
	}
	return ask
}

// tooLarge records an oversized answer to a poll that asked for ask
// commands and returns the new cap and whether to log it now.
func (s *oversizeState) tooLarge(ask int, now time.Time) (capAsk int, logNow bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capAsk = max(ask/2, 1)
	if s.capAsk != s.lastLogCap || s.lastLog.IsZero() || now.Sub(s.lastLog) >= oversizeLogEvery {
		s.lastLog, s.lastLogCap = now, s.capAsk
		return s.capAsk, true
	}
	return s.capAsk, false
}

// ok is a successful poll that asked for ask commands: the cap grows back
// (doubles, and ends once it no longer limits what the poller wants).
func (s *oversizeState) ok(ask, want int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.capAsk == 0 || ask < s.capAsk {
		return
	}
	s.capAsk *= 2
	if s.capAsk >= want {
		s.capAsk = 0
	}
}

// reset lifts the cap: the command that caused it was failed.
func (s *oversizeState) reset() {
	s.mu.Lock()
	s.capAsk = 0
	s.mu.Unlock()
}

// handleOversize reacts to a poll that asked for ask commands and got an
// answer over the size limit.
func (p *CommandPoller) handleOversize(ctx context.Context, ask int, err error) {
	if ask > 1 {
		capAsk, logNow := p.oversize.tooLarge(ask, time.Now())
		if logNow {
			fmt.Printf("[command-poller] The platform's answer to the commands poll is larger than 10 MiB; asking for %d command(s) at a time\n", capAsk)
		}
		return
	}
	// One command and still too large: it is the one to fail.
	_, logNow := p.oversize.tooLarge(1, time.Now())
	var hp ResponseHeadProvider
	var head []byte
	if errors.As(err, &hp) {
		head = hp.ResponseHead()
	}
	id, ok := firstCommandID(head)
	if !ok {
		if logNow {
			fmt.Printf("[command-poller] The platform's answer to the commands poll is larger than 10 MiB even for one command, and its id could not be read from the answer: nothing can be started until the platform drops that command (its lease ends)\n")
		}
		return
	}
	fmt.Printf("[command-poller] Command %s is larger than 10 MiB: failing it so the commands after it can start\n", id)
	p.failOversized(ctx, id)
}

// failOversized fails the command id, which the poll could not carry.
func (p *CommandPoller) failOversized(ctx context.Context, id string) {
	// A shared sensor's ledger lets results through only for a held command;
	// this one was never started, only named by the platform.
	if p.ledger != nil {
		p.ledger.Hold(id, "")
		defer p.ledger.Release(id)
	}
	// A platform that claims on poll holds it for this sensor already;
	// otherwise claim it, so it can be failed like any command. A replay of a
	// transition is accepted.
	if err := p.client.AcknowledgeCommand(ctx, id); err != nil {
		fmt.Printf("[command-poller] Could not claim the oversized command %s to fail it: %v\n", id, err)
		return
	}
	p.refuseCommand(ctx, &Command{ID: id}, errors.New(oversizeReason))
	p.oversize.reset()
}

// firstCommandID reads the id of the first command from the start of a
// truncated GET /commands answer, {"commands":[{"id":"<uuid>", ...}. It
// walks the JSON tokens of what it has and gives up at the first
// surprise, including a head that ends before the id. The id must be a UUID:
// it is the only thing taken from the fragment.
func firstCommandID(head []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(head))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	// Top-level keys until "commands".
	for {
		key, ok := nextKey(dec)
		if !ok {
			return "", false
		}
		if key == "commands" {
			break
		}
		if !skipValue(dec) {
			return "", false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return "", false
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return "", false
	}
	// Keys of the first command until "id" (the platform's field order is
	// not relied on, only that the id is in the head).
	for {
		key, ok := nextKey(dec)
		if !ok {
			return "", false
		}
		if key != "id" {
			if !skipValue(dec) {
				return "", false
			}
			continue
		}
		t, err := dec.Token()
		if err != nil {
			return "", false
		}
		s, isStr := t.(string)
		if !isStr || len(s) != 36 {
			return "", false
		}
		if _, err := uuid.Parse(s); err != nil {
			return "", false
		}
		return s, true
	}
}

// nextKey reads the next object key.
func nextKey(dec *json.Decoder) (string, bool) {
	t, err := dec.Token()
	if err != nil {
		return "", false
	}
	k, ok := t.(string)
	return k, ok
}

// skipValue reads one whole value; false when the head ends inside it.
func skipValue(dec *json.Decoder) bool {
	var raw json.RawMessage
	return dec.Decode(&raw) == nil
}
