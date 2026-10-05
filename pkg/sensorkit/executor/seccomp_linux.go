//go:build linux && (amd64 || arm64)

package executor

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

var errSeccompUnsupported = errors.New("seccomp unsupported")

// seccomp filter return values and the seccomp_data layout (linux/seccomp.h).
const (
	secRetKillProcess = 0x80000000
	secRetErrno       = 0x00050000
	secRetAllow       = 0x7fff0000
	secDataNr         = 0
	secDataArch       = 4
	secDataArg0       = 16 // low 32 bits on little-endian
)

// cloneNamespaceFlags are the clone flags that create namespaces: a task
// may not make its own (they are how sandboxes are escaped or nested).
const cloneNamespaceFlags = unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET | unix.CLONE_NEWCGROUP | unix.CLONE_NEWTIME

// applySeccomp installs the filter: a syscall from another ABI kills the
// task (no 32-bit/x32 table to slip through); the denied syscalls fail with
// EPERM; clone with a namespace flag fails with EPERM; clone3 fails with
// ENOSYS (its flags are behind a pointer the filter cannot read; libc falls
// back to clone); everything else is allowed. no_new_privs must be set.
func applySeccomp() error {
	var f []unix.SockFilter
	stmt := func(code uint16, k uint32) { f = append(f, unix.SockFilter{Code: code, K: k}) }
	jump := func(code uint16, k uint32, jt, jf uint8) {
		f = append(f, unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k})
	}
	const (
		ld   = unix.BPF_LD | unix.BPF_W | unix.BPF_ABS
		jeq  = unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K
		jge  = unix.BPF_JMP | unix.BPF_JGE | unix.BPF_K
		jset = unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K
		ret  = unix.BPF_RET | unix.BPF_K
	)
	eperm := uint32(secRetErrno | uint32(unix.EPERM))
	enosys := uint32(secRetErrno | uint32(unix.ENOSYS))

	stmt(ld, secDataArch)
	jump(jeq, auditArch, 1, 0)
	stmt(ret, secRetKillProcess)
	stmt(ld, secDataNr)
	if x32Bit != 0 {
		jump(jge, x32Bit, 0, 1)
		stmt(ret, secRetKillProcess)
	}
	for _, nr := range deniedSyscalls {
		jump(jeq, uint32(nr), 0, 1) //nolint:gosec // syscall numbers are small
		stmt(ret, eperm)
	}
	jump(jeq, uint32(unix.SYS_CLONE3), 0, 1)
	stmt(ret, enosys)
	// clone: inspect the flags (argument 0 on amd64 and arm64).
	jump(jeq, uint32(unix.SYS_CLONE), 0, 3)
	stmt(ld, secDataArg0)
	jump(jset, uint32(cloneNamespaceFlags), 0, 1)
	stmt(ret, eperm)
	stmt(ret, secRetAllow)

	prog := unix.SockFprog{Len: uint16(len(f)), Filter: &f[0]}                                                              //nolint:gosec // the filter has fewer than 100 instructions
	if err := unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&prog)), 0, 0); err != nil { //nolint:gosec // the seccomp ABI takes a pointer to the program
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOSYS) {
			return errSeccompUnsupported
		}
		return err
	}
	return nil
}

// commonDenied are syscalls no scanner needs: debugging other processes,
// mounting and namespaces, kernel modules and kexec, keyrings, bpf and perf,
// clock and system changes, file handles that bypass path checks,
// userfaultfd.
var commonDenied = []uintptr{
	unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
	unix.SYS_MOUNT, unix.SYS_UMOUNT2, unix.SYS_PIVOT_ROOT, unix.SYS_UNSHARE, unix.SYS_SETNS,
	unix.SYS_OPEN_TREE, unix.SYS_MOVE_MOUNT, unix.SYS_FSOPEN, unix.SYS_FSCONFIG, unix.SYS_FSMOUNT,
	unix.SYS_FSPICK, unix.SYS_MOUNT_SETATTR,
	unix.SYS_INIT_MODULE, unix.SYS_FINIT_MODULE, unix.SYS_DELETE_MODULE,
	unix.SYS_KEXEC_LOAD, unix.SYS_KEXEC_FILE_LOAD, unix.SYS_REBOOT,
	unix.SYS_KEYCTL, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY,
	unix.SYS_BPF, unix.SYS_PERF_EVENT_OPEN,
	unix.SYS_SWAPON, unix.SYS_SWAPOFF, unix.SYS_ACCT, unix.SYS_QUOTACTL,
	unix.SYS_SETTIMEOFDAY, unix.SYS_CLOCK_SETTIME, unix.SYS_ADJTIMEX, unix.SYS_CLOCK_ADJTIME,
	unix.SYS_OPEN_BY_HANDLE_AT, unix.SYS_NAME_TO_HANDLE_AT, unix.SYS_FANOTIFY_INIT,
	unix.SYS_USERFAULTFD, unix.SYS_LOOKUP_DCOOKIE,
}
