package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Inspection is a read-only view of an outbox directory (see Inspect).
type Inspection struct {
	Dir             string
	PendingCount    int
	PendingBytes    int64
	OldestPending   time.Time
	DeadLetters     []DeadLetter
	DeadLetterBytes int64
	// Unreadable counts pending entries Inspect could not read (a write in
	// progress, a torn file, another key); the owning process deals with
	// them.
	Unreadable int
}

// Inspect reads an outbox directory without taking its lock and without
// changing anything, so an operator can look at the outbox of a running
// sensor. It needs the key file only to read the pending items' creation
// times; without it the counts and sizes are still reported. Entries
// changing while it reads are skipped.
func Inspect(dir, keyFile string) (*Inspection, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("outbox: dir is required")
	}
	if _, err := os.Stat(filepath.Join(dir, dirPending)); err != nil {
		return nil, fmt.Errorf("outbox: %s is not an outbox directory: %w", dir, err)
	}
	if keyFile == "" {
		keyFile = filepath.Join(dir, keyName)
	}
	var seal *sealer
	if data, err := os.ReadFile(keyFile); err == nil { //nolint:gosec // operator-supplied path
		if key, err := parseKey(data); err == nil {
			seal, _ = newSealer(key)
		}
	}
	r := &Inspection{Dir: dir}

	names, err := os.ReadDir(filepath.Join(dir, dirPending))
	if err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, n := range names {
		info, err := n.Info()
		if err != nil {
			continue
		}
		id, ok := strings.CutSuffix(n.Name(), itemExt)
		if !ok {
			id, ok = strings.CutSuffix(n.Name(), stateExt)
		}
		if ok && validID(id) {
			sizes[id] += info.Size()
		}
	}
	for id, size := range sizes {
		if _, err := os.Stat(filepath.Join(dir, dirPending, id+itemExt)); err != nil {
			continue // a state without its item: delivered
		}
		r.PendingCount++
		r.PendingBytes += size
		created, ok := inspectCreated(seal, filepath.Join(dir, dirPending, id+stateExt), id)
		if !ok {
			r.Unreadable++
			continue
		}
		if r.OldestPending.IsZero() || created.Before(r.OldestPending) {
			r.OldestPending = created
		}
	}

	dead, err := os.ReadDir(filepath.Join(dir, dirDead))
	if err == nil {
		for _, n := range dead {
			info, err := n.Info()
			if err != nil {
				continue
			}
			r.DeadLetterBytes += info.Size()
			if !strings.HasSuffix(n.Name(), reasonExt) {
				continue
			}
			data, err := readAllLimited(filepath.Join(dir, dirDead, n.Name()), maxReasonFile)
			if err != nil {
				continue
			}
			var dl DeadLetter
			if json.Unmarshal(data, &dl) == nil {
				r.DeadLetters = append(r.DeadLetters, dl)
			}
		}
	}
	sort.Slice(r.DeadLetters, func(i, j int) bool { return r.DeadLetters[i].DeadAt.Before(r.DeadLetters[j].DeadAt) })
	return r, nil
}

func inspectCreated(seal *sealer, statePath, id string) (time.Time, bool) {
	if seal == nil {
		return time.Time{}, false
	}
	data, err := readAllLimited(statePath, maxStateFile)
	if err != nil {
		return time.Time{}, false
	}
	pt, err := seal.open(typeState, id, data)
	if err != nil {
		return time.Time{}, false
	}
	var sf stateFile
	if json.Unmarshal(pt, &sf) != nil || sf.Meta.ID != id {
		return time.Time{}, false
	}
	return sf.Meta.CreatedAt, true
}
