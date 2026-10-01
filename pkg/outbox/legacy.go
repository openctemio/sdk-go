package outbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// osRename is os.Rename (a variable so tests can fail it).
var osRename = os.Rename

// legacyRetryItem is the part of a pre-outbox pkg/retry queue file
// (FileRetryQueue, one JSON file per item) the import needs.
type legacyRetryItem struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Report    json.RawMessage `json:"report"`
	CreatedAt time.Time       `json:"created_at"`
}

// maxLegacyFile bounds one legacy queue file read during the import.
const maxLegacyFile = 256 << 20

// ImportLegacyRetryQueue moves the reports a pre-outbox SDK left in its JSON
// retry queue directory (pkg/retry FileRetryQueue, default
// ~/.openctem/retry-queue) into the outbox, so an upgrade loses nothing. Each
// file is removed only after its report is durably enqueued; a file that is
// not a queue item is left alone. It returns how many reports were imported.
// A missing directory is not an error.
func (o *Outbox) ImportLegacyRetryQueue(dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	if abs, err := filepath.Abs(dir); err == nil {
		if self, err := filepath.Abs(o.cfg.Dir); err == nil && (abs == self || strings.HasPrefix(abs, self+string(filepath.Separator))) {
			return 0, nil // the outbox itself
		}
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("outbox: read legacy queue %s: %w", dir, err)
	}
	n := 0
	var errs []error
	for _, de := range names {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, de.Name())
		data, err := readAllLimited(path, maxLegacyFile)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", de.Name(), err))
			continue
		}
		var it legacyRetryItem
		if json.Unmarshal(data, &it) != nil || len(it.Report) == 0 || string(it.Report) == "null" {
			continue
		}
		switch it.Type {
		case "findings", "assets", "":
		default:
			continue // heartbeats are not worth replaying
		}
		attrs := map[string]string{AttrImportedFrom: "retry-queue"}
		if it.Type == "assets" {
			attrs[AttrAssetsOnly] = "true"
		}
		if _, err := o.Enqueue(Meta{Kind: KindReport, Attrs: attrs}, it.Report); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", de.Name(), err))
			continue
		}
		if err := removeFiles(path); err != nil {
			errs = append(errs, fmt.Errorf("%s: imported but not removed: %w", de.Name(), err))
		}
		n++
	}
	if n > 0 {
		o.cfg.Logf("imported %d report(s) from the old retry queue %s", n, dir)
	}
	return n, errors.Join(errs...)
}

// Attribute keys the SDK sets on Meta.Attrs.
const (
	// AttrAssetsOnly marks a report pushed with PushAssets (findings dropped).
	AttrAssetsOnly = "assets_only"
	// AttrImportedFrom says where an item came from when it was imported.
	AttrImportedFrom = "imported_from"
)
