package bundle

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
)

// State is a consumer's durable progress on one feed.
type State struct {
	Feed string `json:"feed"`
	// Applied is the last sequence applied completely (0: none).
	Applied uint64 `json:"applied"`
	// InProgress is the sequence being applied (0: none). It is never
	// reported as applied until every chunk and Complete succeeded.
	InProgress uint64 `json:"in_progress,omitempty"`
	// Kind and Manifest (sha256 of the manifest envelope) identify the
	// bundle in progress: a resume continues only the same manifest.
	Kind     string `json:"kind,omitempty"`
	Manifest string `json:"manifest,omitempty"`
	// NextChunk is the apply-order index of the next chunk to apply.
	NextChunk int       `json:"next_chunk,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Checkpoint stores a consumer's State. The platform implements it on a
// database table (one row per feed); FileCheckpoint is the file one.
//
// Save after a chunk may be called again with the same State after a
// crash: an Applier's upserts must be idempotent (keyed by record id, and
// never replacing a record of a newer sequence).
type Checkpoint interface {
	Load(ctx context.Context) (State, error)
	Save(ctx context.Context, s State) error
}

// FileCheckpoint stores the State as JSON in one file (0600, written
// crash-safely).
type FileCheckpoint struct{ Path string }

// Load implements Checkpoint; a missing file is the zero State.
func (c FileCheckpoint) Load(context.Context) (State, error) {
	var s State
	b, err := os.ReadFile(c.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) > 1<<16 {
		return s, errors.New("bundle: checkpoint file too large")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("bundle: checkpoint: %w", err)
	}
	return s, nil
}

// Save implements Checkpoint.
func (c FileCheckpoint) Save(_ context.Context, s State) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(c.Path), 0o700); err != nil {
		return err
	}
	return transfer.WriteFileAtomic(c.Path, b)
}
