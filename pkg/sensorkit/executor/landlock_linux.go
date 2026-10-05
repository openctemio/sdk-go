//go:build linux

package executor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errLandlockUnsupported = errors.New("landlock unsupported")

// Landlock file-system rights by ABI version. IOCTL_DEV (ABI 5) is left
// unhandled: tools use ioctls on terminals and /dev/null.
const (
	llReadFile   = unix.LANDLOCK_ACCESS_FS_READ_FILE
	llReadDir    = unix.LANDLOCK_ACCESS_FS_READ_DIR
	llExecute    = unix.LANDLOCK_ACCESS_FS_EXECUTE
	llWriteFile  = unix.LANDLOCK_ACCESS_FS_WRITE_FILE
	llRemoveDir  = unix.LANDLOCK_ACCESS_FS_REMOVE_DIR
	llRemoveFile = unix.LANDLOCK_ACCESS_FS_REMOVE_FILE
	llMakeChar   = unix.LANDLOCK_ACCESS_FS_MAKE_CHAR
	llMakeDir    = unix.LANDLOCK_ACCESS_FS_MAKE_DIR
	llMakeReg    = unix.LANDLOCK_ACCESS_FS_MAKE_REG
	llMakeSock   = unix.LANDLOCK_ACCESS_FS_MAKE_SOCK
	llMakeFifo   = unix.LANDLOCK_ACCESS_FS_MAKE_FIFO
	llMakeBlock  = unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK
	llMakeSym    = unix.LANDLOCK_ACCESS_FS_MAKE_SYM
	llRefer      = unix.LANDLOCK_ACCESS_FS_REFER
	llTruncate   = unix.LANDLOCK_ACCESS_FS_TRUNCATE

	llReadRights = llReadFile | llReadDir | llExecute
	llFileRights = llReadFile | llWriteFile | llExecute | llTruncate
	llV1         = llReadFile | llReadDir | llExecute | llWriteFile | llRemoveDir | llRemoveFile |
		llMakeChar | llMakeDir | llMakeReg | llMakeSock | llMakeFifo | llMakeBlock | llMakeSym
)

// extraWritable are device paths every task may write (where they exist).
var extraWritable = []string{"/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/shm"}

// applyLandlock restricts this process: read and execute everywhere except
// under the deny paths; write (create, remove, truncate, rename) only under
// the write paths. It returns the ABI used.
func applyLandlock(deny, write []string) (int, error) {
	abiRaw, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0, errLandlockUnsupported
	}
	abi := int(abiRaw)
	handled := uint64(llV1)
	if abi >= 2 {
		handled |= llRefer
	}
	if abi >= 3 {
		handled |= llTruncate
	}
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	fdRaw, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0) //nolint:gosec // the landlock ABI takes a pointer to the attribute struct
	if e != 0 {
		if e == unix.ENOSYS || e == unix.EOPNOTSUPP {
			return 0, errLandlockUnsupported
		}
		return 0, fmt.Errorf("create ruleset: %w", e)
	}
	rs := int(fdRaw)
	defer func() { _ = unix.Close(rs) }()

	readable, err := readablePaths(deny)
	if err != nil {
		return 0, err
	}
	if err := addReadable(rs, readable, llReadRights&handled); err != nil {
		return 0, err
	}
	for _, p := range write {
		if under(p, deny) {
			return 0, fmt.Errorf("write path %s is protected", p)
		}
		if err := addPathRule(rs, p, handled); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
	}
	// Devices every task may write, where this system has them (best
	// effort: one that cannot take a rule is left read-only).
	for _, p := range extraWritable {
		_ = addPathRule(rs, p, handled)
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rs), 0, 0); e != 0 {
		return 0, fmt.Errorf("restrict self: %w", e)
	}
	return abi, nil
}

// addPathRule allows access beneath path (for a file, the file rights in
// access only).
// addReadable grants read on each path. A path that disappeared since the
// launcher listed its directory (a sibling task's temporary file in /tmp)
// is skipped: it grants nothing, and must not fail the task.
func addReadable(rs int, paths []string, access uint64) error {
	for _, p := range paths {
		if err := addPathRule(rs, p, access); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func addPathRule(rs int, path string, access uint64) error {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return os.ErrNotExist
		}
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
	case unix.S_IFREG, unix.S_IFCHR, unix.S_IFBLK:
		access &= llFileRights
	default:
		// A pipe, socket or symlink target Landlock cannot take a rule
		// on: nothing to grant.
		return nil
	}
	if access == 0 {
		return nil
	}
	pb := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(fd)}                                                                       //nolint:gosec // a file descriptor fits in int32
	if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rs), unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&pb)), 0, 0, 0); e != 0 { //nolint:gosec // the landlock ABI takes a pointer to the rule
		return fmt.Errorf("add rule %s: %w", path, e)
	}
	return nil
}

// readablePaths is "/" minus the deny paths, as a list of path-beneath
// rules: along the way from "/" to each denied path, every sibling is
// allowed and the denied path itself is not. The directories on that way
// cannot be listed (their entries are reachable by name). An entry created
// later in such a directory is not readable.
func readablePaths(deny []string) ([]string, error) {
	if len(deny) == 0 {
		return []string{"/"}, nil
	}
	type node struct {
		kids   map[string]*node
		denied bool
	}
	root := &node{kids: map[string]*node{}}
	for _, d := range deny {
		n := root
		for _, part := range strings.Split(strings.Trim(filepath.Clean(d), "/"), "/") {
			if part == "" {
				continue
			}
			k, ok := n.kids[part]
			if !ok {
				k = &node{kids: map[string]*node{}}
				n.kids[part] = k
			}
			n = k
		}
		n.denied = true
	}
	var out []string
	var walk func(dir string, n *node) error
	walk = func(dir string, n *node) error {
		entries, err := os.ReadDir(dir)
		if err != nil {
			// Cannot list it: allow nothing beneath (fail closed).
			return nil //nolint:nilerr // an unreadable directory grants nothing
		}
		for _, e := range entries {
			child := filepath.Join(dir, e.Name())
			k, onPath := n.kids[e.Name()]
			switch {
			case !onPath:
				// A symlink (or alias) that leads into a protected path,
				// or to a directory above one, would grant it: skip it
				// (the real path is walked on its own).
				if real, err := filepath.EvalSymlinks(child); err == nil && real != child &&
					(under(real, deny) || aboveAny(real, deny)) {
					continue
				}
				out = append(out, child)
			case k.denied:
				// The protected path itself: nothing.
			default:
				if err := walk(child, k); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk("/", root); err != nil {
		return nil, err
	}
	return out, nil
}

// under reports whether p is, or is beneath, one of paths.
func under(p string, paths []string) bool {
	p = filepath.Clean(p)
	for _, d := range paths {
		if p == d || strings.HasPrefix(p, d+"/") {
			return true
		}
	}
	return false
}

// aboveAny reports whether dir is an ancestor of one of paths.
func aboveAny(dir string, paths []string) bool {
	dir = filepath.Clean(dir)
	for _, p := range paths {
		if dir == "/" || strings.HasPrefix(p, dir+"/") {
			return true
		}
	}
	return false
}
