package outbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// On-disk format (version 1).
//
// Every item is two files in pending/ (or dead/):
//
//	<id>.item   immutable: the item's Meta and its payload
//	<id>.state  mutable:   the Meta again plus the delivery State
//
// Both are sealed the same way:
//
//	magic   4 bytes  "OCOB"
//	version 1 byte   0x01
//	type    1 byte   'I' (item) or 'S' (state)
//	        2 bytes  reserved, zero
//	nonce   12 bytes random
//	sealed  AES-256-GCM(key, nonce, plaintext, aad = the 8 header bytes + id)
//
// The id in the additional data binds a file to its name: a file renamed or
// copied over another item fails authentication and is quarantined instead
// of being delivered as the wrong item.
//
// An item's plaintext is a 4-byte big-endian length, the Meta as JSON and the
// zstd-compressed payload. A state's plaintext is stateFile as JSON.
//
// Every write is: write a temporary file in tmp/, fsync it, rename it into
// place, fsync the directory. A crash leaves either the old file or the new
// one, never a torn file; a torn file from a lying disk fails authentication
// and is quarantined.

const (
	fileMagic        = "OCOB"
	fileVersion      = 1
	typeItem    byte = 'I'
	typeState   byte = 'S'
	headerLen        = 8
	keyLen           = 32

	itemExt   = ".item"
	stateExt  = ".state"
	reasonExt = ".reason.json"

	dirPending = "pending"
	dirDead    = "dead"
	dirCorrupt = "corrupt"
	dirTmp     = "tmp"
	lockName   = ".lock"
	keyName    = "outbox.key"
	keyHeader  = "openctem-outbox-key-v1\n"

	fileMode = 0o600
	dirMode  = 0o700
)

// errCorrupt marks a file that exists but cannot be authenticated or decoded.
var errCorrupt = errors.New("outbox: corrupt or foreign file")

var (
	zEncOnce sync.Once
	zEnc     *zstd.Encoder
	zDecOnce sync.Once
	zDec     *zstd.Decoder
)

func encoder() *zstd.Encoder {
	zEncOnce.Do(func() {
		// Single-threaded and deterministic: the same payload compresses to
		// the same bytes, which keeps v2 Content-Digests stable across
		// retries of one SDK build.
		zEnc, _ = zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithEncoderLevel(zstd.SpeedDefault))
	})
	return zEnc
}

func decoder() *zstd.Decoder {
	zDecOnce.Do(func() {
		zDec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(1<<31))
	})
	return zDec
}

// sealer encrypts and authenticates outbox files.
type sealer struct{ aead cipher.AEAD }

func newSealer(key []byte) (*sealer, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("outbox: key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &sealer{aead: aead}, nil
}

func fileHeader(t byte) []byte {
	return []byte{fileMagic[0], fileMagic[1], fileMagic[2], fileMagic[3], fileVersion, t, 0, 0}
}

// maxItemBytes bounds one item file: an item can never be larger than the
// whole outbox, and the bound keeps every size sum below int overflow.
const maxItemBytes = DefaultMaxBytes

// errItemTooLarge is returned for an item that could never fit the outbox.
var errItemTooLarge = errors.New("outbox: item larger than the outbox size limit")

func (s *sealer) seal(t byte, id string, plaintext []byte) ([]byte, error) {
	if len(plaintext) > maxItemBytes || len(id) > maxItemBytes {
		return nil, errItemTooLarge
	}
	hdr := fileHeader(t)
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("outbox: nonce: %w", err)
	}
	out := make([]byte, 0, len(hdr)+len(nonce)+len(plaintext)+s.aead.Overhead())
	out = append(out, hdr...)
	out = append(out, nonce...)
	return s.aead.Seal(out, nonce, plaintext, append(hdr, id...)), nil
}

func (s *sealer) open(t byte, id string, data []byte) ([]byte, error) {
	ns := s.aead.NonceSize()
	if len(data) < headerLen+ns+s.aead.Overhead() {
		return nil, errCorrupt
	}
	hdr := data[:headerLen]
	if !bytes.Equal(hdr, fileHeader(t)) {
		return nil, errCorrupt
	}
	pt, err := s.aead.Open(nil, data[headerLen:headerLen+ns], data[headerLen+ns:], append(append([]byte{}, hdr...), id...))
	if err != nil {
		return nil, errCorrupt
	}
	return pt, nil
}

// encodeItem builds an item file's plaintext.
func encodeItem(m Meta, payload []byte) ([]byte, error) {
	mj, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	comp := encoder().EncodeAll(payload, nil)
	if len(mj) > maxItemBytes || len(comp) > maxItemBytes {
		return nil, errItemTooLarge
	}
	buf := make([]byte, 4, 4+len(mj)+len(comp))
	binary.BigEndian.PutUint32(buf, uint32(len(mj))) //nolint:gosec // meta JSON is far below 4 GiB
	buf = append(buf, mj...)
	return append(buf, comp...), nil
}

// decodeItem splits an item file's plaintext. withPayload=false skips the
// decompression when only the Meta is needed.
func decodeItem(pt []byte, withPayload bool) (Meta, []byte, error) {
	var m Meta
	if len(pt) < 4 {
		return m, nil, errCorrupt
	}
	n := int(binary.BigEndian.Uint32(pt))
	if n <= 0 || 4+n > len(pt) {
		return m, nil, errCorrupt
	}
	if err := json.Unmarshal(pt[4:4+n], &m); err != nil {
		return m, nil, errCorrupt
	}
	if !withPayload {
		return m, nil, nil
	}
	payload, err := decoder().DecodeAll(pt[4+n:], nil)
	if err != nil {
		return m, nil, errCorrupt
	}
	return m, payload, nil
}

// stateFile is the plaintext of a .state file.
type stateFile struct {
	Meta  Meta  `json:"meta"`
	State State `json:"state"`
	// ItemSize is the sealed item file's size: a truncated item (power loss
	// on a disk that lied about fsync) is caught at Open without decrypting
	// every item.
	ItemSize int64 `json:"item_size"`
}

// writeAtomic writes data to dir/name crash-safely: temporary file in tmpDir,
// fsync, rename, fsync dir.
func writeAtomic(tmpDir, dir, name string, data []byte) error {
	var rnd [8]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := filepath.Join(tmpDir, name+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

// removeFiles removes paths (missing ones are fine) and fsyncs their
// directories.
func removeFiles(paths ...string) error {
	dirs := map[string]bool{}
	var firstErr error
	for _, p := range paths {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
		dirs[filepath.Dir(p)] = true
	}
	for d := range dirs {
		if err := syncDir(d); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// loadOrCreateKey reads the key file, or creates it with a fresh random key.
// created reports a new key, so the caller can warn when items already exist
// (they were sealed with a key that is gone and will be quarantined).
func loadOrCreateKey(path, tmpDir string) (key []byte, created bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err == nil {
		key, perr := parseKey(data)
		if perr != nil {
			return nil, false, fmt.Errorf("outbox: key file %s: %w", path, perr)
		}
		if fi, serr := os.Stat(path); serr == nil && fi.Mode().Perm()&0o077 != 0 {
			// Tighten rather than refuse: a key readable by others is the
			// operator's mistake, and refusing would stop the sensor.
			_ = os.Chmod(path, fileMode)
		}
		return key, false, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, false, fmt.Errorf("outbox: read key file: %w", err)
	}
	key = make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("outbox: generate key: %w", err)
	}
	content := []byte(keyHeader + hex.EncodeToString(key) + "\n")
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return nil, false, fmt.Errorf("outbox: key dir: %w", err)
	}
	if tmpDir == "" {
		tmpDir = dir
	}
	// O_EXCL on the final name through a link: two processes racing to
	// create the key must not end up with different keys. The directory lock
	// already prevents that for the default key location; the link keeps it
	// true for a key file shared outside the outbox directory.
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(tmpDir, keyName+"."+hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // our own tmp path
	if err != nil {
		return nil, false, fmt.Errorf("outbox: create key: %w", err)
	}
	_, werr := f.Write(content)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return nil, false, fmt.Errorf("outbox: write key: %w", errors.Join(werr, serr, cerr))
	}
	if err := os.Link(tmp, path); err != nil {
		_ = os.Remove(tmp)
		if errors.Is(err, fs.ErrExist) {
			return loadOrCreateKey(path, tmpDir)
		}
		// File systems without hard links: fall back to rename.
		if err := os.Rename(tmp, path); err != nil {
			return nil, false, fmt.Errorf("outbox: install key: %w", err)
		}
	} else {
		_ = os.Remove(tmp)
	}
	_ = syncDir(dir)
	return key, true, nil
}

func parseKey(data []byte) ([]byte, error) {
	s := string(data)
	rest, ok := strings.CutPrefix(s, keyHeader)
	if !ok {
		return nil, errors.New("not an outbox key file")
	}
	key, err := hex.DecodeString(strings.TrimSpace(rest))
	if err != nil || len(key) != keyLen {
		return nil, errors.New("malformed key")
	}
	return key, nil
}

// readAllLimited reads a file of at most limit bytes.
func readAllLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // paths inside the outbox directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errCorrupt
	}
	return data, nil
}
