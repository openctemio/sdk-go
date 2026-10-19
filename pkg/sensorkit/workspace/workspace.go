// Package workspace gives each job a private working directory on the
// sensor's data volume (openctem research 194 §5.4 (4)):
//
//	<root>/<tenant>/<job>-<random>/
//
// Every level is 0700 and owned by the sensor's user (a root or tenant
// directory owned by someone else, or a symbolic link, is refused). A job's
// directory is never shared with another job, of the same organization or,
// on a shared sensor, of another one. Usage is measured against a byte cap
// while the job runs (Watch); Close removes the directory; Sweep removes
// whatever a crash left behind; EraseTenant removes an organization's
// directories when it leaves a shared sensor.
//
// The process backend of the executor still hides sibling directories from
// a task; this package decides where the directories live and how long.
//
// Stability: Experimental (docs/STABILITY.md).
package workspace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

// DefaultMaxBytes caps one job's workspace.
const DefaultMaxBytes = 2 << 30

// Errors.
var (
	ErrInvalidName = errors.New("workspace: invalid tenant or job name")
	ErrNotPrivate  = errors.New("workspace: directory is not private to the sensor")
	ErrQuota       = errors.New("workspace: job exceeded its workspace quota")
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)

func validName(s string) error {
	if !nameRE.MatchString(s) || strings.Contains(s, "..") {
		return fmt.Errorf("%w: %q", ErrInvalidName, s)
	}
	return nil
}

// Manager owns the workspace root.
type Manager struct {
	root string
	mu   sync.Mutex
	live map[string]*Workspace // dir -> workspace
}

// Open makes (or checks) the private root directory.
func Open(root string) (*Manager, error) {
	root = filepath.Clean(root)
	if err := ensurePrivate(root); err != nil {
		return nil, err
	}
	return &Manager{root: root, live: map[string]*Workspace{}}, nil
}

// Root is the workspace root.
func (m *Manager) Root() string { return m.root }

// Noexec reports whether the root's volume is mounted noexec (a tool cannot
// run a binary a target made it download); known=false when the platform
// cannot tell. A non-root sensor cannot remount: doctor reports it.
func (m *Manager) Noexec() (on, known bool) { return noexec(m.root) }

// ensurePrivate creates dir 0700 when missing and refuses a symbolic link,
// a non-directory or another user's directory; a mode that lets others in
// is narrowed.
func ensurePrivate(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("workspace: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrNotPrivate, dir)
	}
	if ownedByOther(fi) {
		return fmt.Errorf("%w: %s belongs to another user", ErrNotPrivate, dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // our own directory, checked above
			return fmt.Errorf("workspace: %w", err)
		}
	}
	return nil
}

// Limits bound one workspace.
type Limits struct {
	// MaxBytes caps the bytes a job may keep (0: DefaultMaxBytes).
	MaxBytes int64
}

// Workspace is one job's directory.
type Workspace struct {
	m      *Manager
	tenant string
	job    string
	dir    string
	lim    Limits
	once   sync.Once
}

// Create makes a new private directory for one job of one tenant.
func (m *Manager) Create(tenant, job string, lim Limits) (*Workspace, error) {
	if err := validName(tenant); err != nil {
		return nil, err
	}
	if err := validName(job); err != nil {
		return nil, err
	}
	if lim.MaxBytes <= 0 {
		lim.MaxBytes = DefaultMaxBytes
	}
	tdir := filepath.Join(m.root, tenant)
	if err := ensurePrivate(tdir); err != nil {
		return nil, err
	}
	var rnd [6]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return nil, fmt.Errorf("workspace: %w", err)
	}
	dir := filepath.Join(tdir, job+"-"+hex.EncodeToString(rnd[:]))
	if err := os.Mkdir(dir, 0o700); err != nil { // never an existing directory
		return nil, fmt.Errorf("workspace: %w", err)
	}
	w := &Workspace{m: m, tenant: tenant, job: job, dir: dir, lim: lim}
	m.mu.Lock()
	m.live[dir] = w
	m.mu.Unlock()
	return w, nil
}

// Dir is the job's directory.
func (w *Workspace) Dir() string { return w.dir }

// Usage returns the bytes under the directory (symbolic links are not
// followed and count as their own size).
func (w *Workspace) Usage() int64 { return usage(w.dir) }

func usage(dir string) int64 {
	var n int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // a file removed during the walk
		}
		if info, ierr := d.Info(); ierr == nil && !d.IsDir() {
			n += info.Size()
		}
		return nil
	})
	return n
}

// Watch measures the workspace every interval until ctx ends and calls
// onExceed once (with the usage) when it goes over the cap; the caller
// cancels the job with ErrQuota.
func (w *Workspace) Watch(ctx context.Context, interval time.Duration, onExceed func(used int64)) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if used := w.Usage(); used > w.lim.MaxBytes {
					onExceed(used)
					return
				}
			}
		}
	}()
}

// Close removes the directory and everything in it (a task may have made
// files read-only). Safe to call more than once.
func (w *Workspace) Close() error {
	var err error
	w.once.Do(func() {
		err = removeAll(w.dir)
		w.m.mu.Lock()
		delete(w.m.live, w.dir)
		w.m.mu.Unlock()
	})
	return err
}

// beforeChmod is a test hook called with each directory path just before
// removeAll makes it writable.
var beforeChmod func(path string)

// removeAll removes dir after making every directory in it writable. A
// task running in the workspace can replace a directory by a symbolic link
// at any moment, so nothing here resolves a path outside dir: the walk and
// every chmod and removal go through an os.Root (openat semantics), which
// refuses a link that leaves it, and a link is removed as a link.
func removeAll(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() { // a file or a link: remove it, never follow it
		return os.Remove(dir)
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer r.Close()
	if rfi, serr := r.Stat("."); serr != nil || !os.SameFile(fi, rfi) {
		return fmt.Errorf("workspace: %s changed while it was being removed", dir)
	}
	_ = r.Chmod(".", 0o700) //nolint:gosec // our own directory, made removable
	_ = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, werr error) error {
		if werr == nil && d.IsDir() && p != "." {
			if beforeChmod != nil {
				beforeChmod(filepath.Join(dir, filepath.FromSlash(p)))
			}
			_ = r.Chmod(p, 0o700) //nolint:gosec // our own directory, made removable
		}
		return nil
	})
	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if rerr := r.RemoveAll(e.Name()); rerr != nil {
			return rerr
		}
	}
	_ = r.Close()
	return os.Remove(dir)
}

// Sweep removes every job directory not created by this process and not
// kept by keep (called with the tenant and the job name; nil keeps
// nothing), and any stray file in the root. Run it at start, after the
// journal's recovery, so a crash leaves nothing behind.
func (m *Manager) Sweep(keep func(tenant, job string) bool) (int, error) {
	return m.SweepBounded(context.Background(), keep, 0)
}

// SweepBounded is Sweep that stops when ctx ends or after limit removals
// (0: no limit); what is left is removed by the next call.
func (m *Manager) SweepBounded(ctx context.Context, keep func(tenant, job string) bool, limit int) (int, error) {
	tenants, err := os.ReadDir(m.root)
	if err != nil {
		return 0, err
	}
	removed := 0
	stop := func() bool { return ctx.Err() != nil || (limit > 0 && removed >= limit) }
	for _, t := range tenants {
		if stop() {
			return removed, ctx.Err()
		}
		tdir := filepath.Join(m.root, t.Name())
		if !t.IsDir() || validName(t.Name()) != nil {
			if removeAll(tdir) == nil {
				removed++
			}
			continue
		}
		jobs, err := os.ReadDir(tdir)
		if err != nil {
			continue
		}
		for _, j := range jobs {
			if stop() {
				return removed, ctx.Err()
			}
			dir := filepath.Join(tdir, j.Name())
			m.mu.Lock()
			_, live := m.live[dir]
			m.mu.Unlock()
			if live {
				continue
			}
			job := j.Name()
			if i := strings.LastIndexByte(job, '-'); i > 0 {
				job = job[:i]
			}
			if keep != nil && j.IsDir() && keep(t.Name(), job) {
				continue
			}
			if removeAll(dir) == nil {
				removed++
			}
		}
	}
	return removed, nil
}

// Bytes is what every job directory holds now (links are not followed).
func (m *Manager) Bytes() int64 { return usage(m.root) }

// EraseTenant removes every directory of a tenant, including those in use
// (the caller stops the tenant's jobs first).
func (m *Manager) EraseTenant(tenant string) error {
	if err := validName(tenant); err != nil {
		return err
	}
	tdir := filepath.Join(m.root, tenant)
	m.mu.Lock()
	for dir := range m.live {
		if strings.HasPrefix(dir, tdir+string(os.PathSeparator)) {
			delete(m.live, dir)
		}
	}
	m.mu.Unlock()
	return removeAll(tdir)
}

// The janitor sweeps the workspaces through this interface.
var _ localstore.Workspaces = (*Manager)(nil)
