package localstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// On-disk record format (version 1):
//
//	magic   4 bytes  "OCLS"
//	version 1 byte   0x01
//	kind    1 byte   kindKV, kindMeta, kindSealer or kindWrappedKey
//	        2 bytes  reserved, zero
//	nonce   12 bytes random
//	sealed  AES-256-GCM(key, nonce, plaintext, aad)
//
//	aad = the 8 header bytes || u16 len || purpose || u16 len || tenant ||
//	      u16 len || namespace || u16 len || name
//
// Length prefixes keep the binding unambiguous ("a"+"bc" never equals
// "ab"+"c").
const (
	recMagic   = "OCLS"
	recVersion = 1
	headerLen  = 8
	nonceLen   = 12
	keyLen     = 32

	kindKV         byte = 'K'
	kindMeta       byte = 'M'
	kindSealer     byte = 'X'
	kindWrappedKey byte = 'W'

	fileMode = 0o600
	dirMode  = 0o700
)

func recHeader(kind byte) []byte {
	return []byte{recMagic[0], recMagic[1], recMagic[2], recMagic[3], recVersion, kind, 0, 0}
}

// binding is what a record's additional data binds it to.
type binding struct {
	purpose, tenant, namespace, name string
}

func (b binding) aad(hdr []byte) []byte {
	out := make([]byte, 0, len(hdr)+8+len(b.purpose)+len(b.tenant)+len(b.namespace)+len(b.name))
	out = append(out, hdr...)
	for _, s := range []string{b.purpose, b.tenant, b.namespace, b.name} {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s))) //nolint:gosec // every part is validated far below 64 KiB
		out = append(out, s...)
	}
	return out
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != keyLen {
		return nil, fmt.Errorf("localstore: key must be %d bytes", keyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// seal encrypts plaintext into a record.
func seal(aead cipher.AEAD, kind byte, b binding, plaintext []byte) ([]byte, error) {
	if len(plaintext) > maxRecordBytes {
		return nil, ErrTooLarge
	}
	hdr := recHeader(kind)
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("localstore: nonce: %w", err)
	}
	out := make([]byte, 0, headerLen+nonceLen+len(plaintext)+aead.Overhead())
	out = append(out, hdr...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, b.aad(hdr)), nil
}

// errAuth is a record that is not a well-formed record of this kind sealed
// for this binding.
var errAuth = errors.New("localstore: record failed authentication")

// open authenticates and decrypts a record.
func open(aead cipher.AEAD, kind byte, b binding, data []byte) ([]byte, error) {
	if len(data) < headerLen+nonceLen+aead.Overhead() {
		return nil, errAuth
	}
	hdr := data[:headerLen]
	if !bytes.Equal(hdr, recHeader(kind)) {
		return nil, errAuth
	}
	pt, err := aead.Open(nil, data[headerLen:headerLen+nonceLen], data[headerLen+nonceLen:], b.aad(hdr))
	if err != nil {
		return nil, errAuth
	}
	return pt, nil
}

// writeAtomic writes data to path through a temporary file in tmpDir:
// write, fsync, rename, fsync the directory. A crash leaves the old file or
// the new one.
func writeAtomic(tmpDir, path string, data []byte) error {
	var rnd [8]byte
	_, _ = rand.Read(rnd[:])
	tmp := filepath.Join(tmpDir, hex.EncodeToString(rnd[:])+".tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // our own tmp path
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := mkdirSynced(filepath.Dir(path)); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(filepath.Dir(path))
}

// writeSynced creates path (O_EXCL, 0600), writes data and fsyncs it.
func writeSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode) //nolint:gosec // our own path
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	return errors.Join(werr, serr, f.Close())
}

// mkdirSynced creates dir and any missing parents (0700) and fsyncs the
// parent of every directory it created, so a record renamed into a new
// directory survives a crash together with the directory entry.
func mkdirSynced(dir string) error {
	dir = filepath.Clean(dir)
	var created []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		created = append(created, d)
		if filepath.Dir(d) == d {
			break
		}
	}
	if len(created) == 0 {
		return nil
	}
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return err
	}
	for i := len(created) - 1; i >= 0; i-- {
		if err := syncDir(filepath.Dir(created[i])); err != nil {
			return err
		}
	}
	return nil
}

// readBounded reads at most limit bytes of path; a larger file is errAuth
// (nothing this store wrote can be that large).
func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a path inside the store, built from validated parts
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errAuth
	}
	return data, nil
}
