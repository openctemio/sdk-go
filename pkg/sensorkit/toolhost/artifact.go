package toolhost

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
)

// readRegular reads a regular file of exactly size bytes without following
// a symlink at its last component, and returns its SHA-256.
func readRegular(path string, size int64) ([]byte, string, error) {
	f, err := openNoFollow(path)
	if err != nil {
		return nil, "", errors.New("cannot open (not a plain file?)")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		return nil, "", errors.New("not a regular file")
	}
	if st.Size() != size {
		return nil, "", errors.New("size differs from the announced size")
	}
	data, err := io.ReadAll(io.LimitReader(f, size+1))
	if err != nil {
		return nil, "", err
	}
	if int64(len(data)) != size {
		return nil, "", errors.New("size differs from the announced size")
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}
