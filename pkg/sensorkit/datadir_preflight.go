package sensorkit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// DataDirDocsURL is where the data directory problem is explained.
const DataDirDocsURL = "https://docs.openctem.io/sensors/troubleshooting/#permission-denied-on-varlibopenctem"

// DataDirProblem is a data directory the sensor cannot use. Its Error is the
// message to print: the path, who owns it, who the sensor runs as and the
// two ways out.
type DataDirProblem struct {
	// Path is the directory the sensor needs.
	Path string
	// Cause is what the operating system said.
	Cause error
	// Blocked is the existing directory (Path or its nearest existing
	// parent) whose owner and mode stopped the sensor; empty when none exists.
	Blocked string
	// OwnerUID and OwnerGID own Blocked (-1 when unknown); Mode is its
	// permission bits.
	OwnerUID, OwnerGID int
	Mode               fs.FileMode
	// UID and GID are the sensor's own.
	UID, GID int
}

func (p *DataDirProblem) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the sensor's data directory is not usable: %s\n", p.Cause)
	fmt.Fprintf(&b, "  path:               %s\n", p.Path)
	if p.Blocked != "" {
		if p.OwnerUID >= 0 {
			fmt.Fprintf(&b, "  owner of %s: uid %d, gid %d (mode %04o)\n", p.Blocked, p.OwnerUID, p.OwnerGID, p.Mode.Perm())
		} else {
			fmt.Fprintf(&b, "  existing directory: %s (mode %04o)\n", p.Blocked, p.Mode.Perm())
		}
	}
	fmt.Fprintf(&b, "  the sensor runs as: uid %d, gid %d\n", p.UID, p.GID)
	b.WriteString("Fix it in one of two ways:\n")
	fmt.Fprintf(&b, "  1. A bind mount (-v /host/dir:%s): give the sensor's user the host directory:\n", DefaultDataDir)
	fmt.Fprintf(&b, "       sudo chown -R %d:%d /host/dir\n", p.UID, p.GID)
	fmt.Fprintf(&b, "  2. A named volume (recommended; Docker sets the owner): -v openctem-sensor-data:%s\n", DefaultDataDir)
	fmt.Fprintf(&b, "See %s", DataDirDocsURL)
	return b.String()
}

func (p *DataDirProblem) Unwrap() error { return p.Cause }

// DataDirs lists the directories a daemon needs: the outbox, state, store,
// workspaces and (when contentDir is not empty) content directories, from
// their environment variables or their defaults under DefaultDataDir. The
// defaults are included only when DefaultDataDir exists (the images create
// it); a sensor run as a plain binary without it falls back to ~/.openctem,
// as before.
func DataDirs(contentDir string) []string {
	_, statErr := os.Stat(DefaultDataDir)
	dataDirExists := statErr == nil

	var dirs []string
	add := func(explicit, def string, defaultInUse bool) {
		switch {
		case strings.TrimSpace(explicit) != "":
			dirs = append(dirs, strings.TrimSpace(explicit))
		case defaultInUse:
			dirs = append(dirs, def)
		}
	}
	// The store and the workspaces sit beside the outbox directory.
	outbox := strings.TrimSpace(os.Getenv(EnvOutboxDir))
	base := DefaultDataDir
	if outbox != "" {
		base = filepath.Dir(outbox)
	}
	besideOutbox := outbox != "" || dataDirExists
	add(outbox, DefaultOutboxDir, dataDirExists)
	add(os.Getenv(EnvStateDir), DefaultDataDir+"/state", dataDirExists)
	add(os.Getenv(EnvStoreDir), filepath.Join(base, "store"), besideOutbox)
	add(os.Getenv(EnvWorkspaceDir), filepath.Join(base, "workspaces"), besideOutbox)
	if contentDir != "" {
		dirs = append(dirs, contentDir)
	}
	return dirs
}

// CheckDataDirs makes sure each directory exists (it is created 0700) and
// that the sensor can create a file in it. It returns a *DataDirProblem for
// the first one that fails, nil when all are usable.
func CheckDataDirs(dirs ...string) error {
	for _, dir := range dirs {
		if err := checkDataDir(dir); err != nil {
			return err
		}
	}
	return nil
}

// PreflightDataDirs is CheckDataDirs over DataDirs(contentDir): the check a
// daemon runs before anything else, so a data directory its user cannot
// write stops it with one clear message instead of a crash loop.
func PreflightDataDirs(contentDir string) error {
	return CheckDataDirs(DataDirs(contentDir)...)
}

func checkDataDir(dir string) error {
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		var f *os.File
		if f, err = os.CreateTemp(dir, ".preflight-*"); err == nil {
			name := f.Name()
			_ = f.Close()
			err = os.Remove(name)
		}
	}
	if err == nil {
		return nil
	}
	return newDataDirProblem(dir, err)
}

func newDataDirProblem(dir string, cause error) *DataDirProblem {
	p := &DataDirProblem{
		Path: dir, Cause: cause,
		OwnerUID: -1, OwnerGID: -1,
		UID: os.Getuid(), GID: os.Getgid(),
	}
	// The directory that stopped us: the nearest one that exists.
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if fi, err := os.Stat(d); err == nil {
			p.Blocked, p.Mode = d, fi.Mode()
			if uid, gid, ok := dirOwner(fi); ok {
				p.OwnerUID, p.OwnerGID = uid, gid
			}
			if !fi.IsDir() {
				p.Cause = errors.New(d + " is not a directory")
			}
			break
		}
		if d == filepath.Dir(d) {
			break
		}
	}
	return p
}
