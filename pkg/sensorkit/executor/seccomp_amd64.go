//go:build linux && amd64

package executor

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_X86_64

// x32Bit marks the x32 syscall ABI on amd64: refused.
const x32Bit = 0x40000000

var deniedSyscalls = append([]uintptr{unix.SYS_IOPL, unix.SYS_IOPERM, unix.SYS_MODIFY_LDT, unix.SYS_USELIB}, commonDenied...)
