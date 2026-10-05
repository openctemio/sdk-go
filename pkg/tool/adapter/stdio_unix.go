//go:build unix

package adapter

import (
	"os"

	"golang.org/x/sys/unix"
)

// protectStdout keeps the protocol channel to itself: it returns a new
// descriptor for the original stdout and points fd 1 at stderr, so a stray
// fmt.Print in tool code cannot corrupt the protocol.
func protectStdout() (*os.File, error) {
	fd, err := unix.Dup(1)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(fd)
	if err := unix.Dup2(2, 1); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "protocol"), nil
}
