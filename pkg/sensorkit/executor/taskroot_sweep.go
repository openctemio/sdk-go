package executor

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// A task directory can hold what a tool was given for its run (a provider
// configuration it wrote, a credential file): it is removed when the task
// ends. A sensor that crashed leaves its task directories behind, so each
// process marks the directories it makes with its instance (a random id
// whose owner file it keeps locked while it runs), and SweepStaleTaskDirs
// removes, at start, the directories of instances that no longer run. A
// directory without a mark (made by an older release) is removed once it
// is older than staleUnmarkedAge.

// staleUnmarkedAge is the age past which a task directory without an
// instance mark is taken as left behind.
const staleUnmarkedAge = 24 * time.Hour

const ownerFilePrefix = ".owner-"

var (
	instanceOnce sync.Once
	instanceID   string
	// instanceLock keeps this instance's owner file locked for the life of
	// the process (nil where locks are not available).
	instanceLock *os.File
	instanceMark = regexp.MustCompile(`\.i([0-9a-f]{16})\.`)
)

// instance returns this process's instance id, creating and locking its
// owner file in root on first use; "" when the owner file cannot be held
// (this process's directories are then unmarked: swept by age only, never
// taken for a dead instance's).
func instance(root string) string {
	instanceOnce.Do(func() {
		if ensurePrivateDir(root) != nil {
			return
		}
		var b [8]byte
		if _, err := rand.Read(b[:]); err != nil {
			return
		}
		id := hex.EncodeToString(b[:])
		if instanceLock = lockOwnerFile(filepath.Join(root, ownerFilePrefix+id)); instanceLock != nil {
			instanceID = id
		}
	})
	return instanceID
}

// instancePrefix marks a task directory name with this instance.
func instancePrefix(root, prefix string) string {
	if id := instance(root); id != "" {
		return prefix + ".i" + id + "."
	}
	return prefix + "-"
}

// SweepStaleTaskDirs removes the task directories under TaskRoot that no
// running sensor owns: those of an instance whose owner file is no longer
// locked (it exited or crashed), and unmarked ones older than a day. It
// returns how many it removed. Call it once at start.
func SweepStaleTaskDirs() (int, error) {
	root := TaskRoot()
	if err := ensurePrivateDir(root); err != nil {
		return 0, err
	}
	ours := instance(root)
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	gone := map[string]bool{}
	ownerGone := func(id string) bool {
		g, ok := gone[id]
		if !ok {
			g = ownerFileGone(filepath.Join(root, ownerFilePrefix+id))
			gone[id] = g
		}
		return g
	}
	removed := 0
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, ownerFilePrefix) {
			continue
		}
		path := filepath.Join(root, name)
		if m := instanceMark.FindStringSubmatch(name); m != nil {
			if (ours != "" && m[1] == ours) || !ownerGone(m[1]) {
				continue
			}
		} else if fi, err := e.Info(); err != nil || time.Since(fi.ModTime()) < staleUnmarkedAge {
			continue
		}
		if os.RemoveAll(path) == nil {
			removed++
		}
	}
	for id, g := range gone {
		if g {
			_ = os.Remove(filepath.Join(root, ownerFilePrefix+id))
		}
	}
	return removed, nil
}
