package localstore

import "fmt"

// space is a volume's free and total bytes and inodes (0 when unknown).
type space struct {
	freeBytes, totalBytes uint64
	freeFiles, totalFiles uint64
}

// DiskLevel is how much room the store's volume has left.
type DiskLevel string

// Disk levels.
const (
	// DiskOK: room to accept work.
	DiskOK DiskLevel = "ok"
	// DiskLow: stop accepting new work (claim nothing); running jobs finish
	// and their results go to the outbox within its caps.
	DiskLow DiskLevel = "low"
	// DiskCritical: only critical writes (journal and state updates) and
	// deletions; everything else is refused with ErrDiskFull.
	DiskCritical DiskLevel = "critical"
	// DiskUnknown: the platform cannot tell; treated as ok.
	DiskUnknown DiskLevel = "unknown"
)

// minFreeFiles is the free-inode floor below which the volume is critical
// (an exhausted inode table fails every create like a full disk).
const (
	minFreeFilesCritical = 100
	minFreeFilesLow      = 1000
)

// DiskState is the store volume's state.
type DiskState struct {
	Level      DiskLevel `json:"level"`
	FreeBytes  uint64    `json:"free_bytes,omitempty"`
	TotalBytes uint64    `json:"total_bytes,omitempty"`
	FreeFiles  uint64    `json:"free_files,omitempty"`
	// Reason says why the level is not ok, in one line.
	Reason string `json:"reason,omitempty"`
}

// Disk reports the free space of the store's volume.
func (s *Store) Disk() DiskState {
	sp, ok := s.opts.space(s.dir)
	if !ok {
		return DiskState{Level: DiskUnknown}
	}
	st := DiskState{Level: DiskOK, FreeBytes: sp.freeBytes, TotalBytes: sp.totalBytes, FreeFiles: sp.freeFiles}
	lowMark := uint64(s.opts.MinFreeBytes) //nolint:gosec // defaults make it positive
	if frac := uint64(float64(sp.totalBytes) * s.opts.MinFreeFraction); frac > lowMark {
		lowMark = frac
	}
	critMark := uint64(s.opts.CriticalFreeBytes) //nolint:gosec // defaults make it positive
	hasInodes := sp.totalFiles > 0
	switch {
	case sp.freeBytes < critMark:
		st.Level = DiskCritical
		st.Reason = fmt.Sprintf("%d MiB free, below the critical mark of %d MiB", sp.freeBytes>>20, critMark>>20)
	case hasInodes && sp.freeFiles < minFreeFilesCritical:
		st.Level = DiskCritical
		st.Reason = fmt.Sprintf("%d free inodes", sp.freeFiles)
	case sp.freeBytes < lowMark:
		st.Level = DiskLow
		st.Reason = fmt.Sprintf("%d MiB free, below the low mark of %d MiB", sp.freeBytes>>20, lowMark>>20)
	case hasInodes && sp.freeFiles < minFreeFilesLow:
		st.Level = DiskLow
		st.Reason = fmt.Sprintf("%d free inodes", sp.freeFiles)
	}
	return st
}

// AcceptsWork reports whether the volume has room for new work (DiskOK or
// DiskUnknown), with the reason when it does not.
func (s *Store) AcceptsWork() (bool, string) {
	d := s.Disk()
	if d.Level == DiskLow || d.Level == DiskCritical {
		return false, d.Reason
	}
	return true, ""
}
