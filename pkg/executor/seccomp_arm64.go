//go:build linux && arm64

package executor

import "golang.org/x/sys/unix"

const auditArch = unix.AUDIT_ARCH_AARCH64

// x32Bit: arm64 has no second syscall ABI to refuse (aarch32 is a separate
// audit arch, refused by the arch check).
const x32Bit = 0

var deniedSyscalls = commonDenied
