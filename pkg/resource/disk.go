package resource

// DiskFree returns the bytes available to an unprivileged user on dir's
// file system; 0 when it cannot be read (or on a system without statfs).
func DiskFree(dir string) int64 { return diskFree(dir) }
