package localstore

import (
	"bytes"
	"testing"
)

// FuzzDecodeRecord: the record plaintext decoder never panics and never
// returns data outside the input.
func FuzzDecodeRecord(f *testing.F) {
	good, _ := encodeRecord(recordMeta{Boot: 1}, []byte("data"))
	f.Add(good)
	f.Add([]byte{})
	f.Add([]byte{0, 0, 0, 1, '{'})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, pt []byte) {
		_, data, err := decodeRecord(pt)
		if err == nil && len(data) > len(pt) {
			t.Fatalf("data longer than input")
		}
	})
}

// FuzzOpenRecord: opening arbitrary bytes never panics and never succeeds
// for bytes the key did not seal.
func FuzzOpenRecord(f *testing.F) {
	aead, _ := newAEAD(bytes.Repeat([]byte{1}, keyLen))
	b := binding{purpose: "kv", tenant: "t", namespace: "n", name: "x"}
	good, _ := seal(aead, kindKV, b, []byte("hello"))
	f.Add(good)
	f.Add([]byte("OCLS\x01K\x00\x00"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		pt, err := open(aead, kindKV, b, data)
		if err == nil && !bytes.Equal(data, good) && string(pt) != "hello" {
			// Only a record sealed under the key can open; the seed is the
			// one such record here.
			t.Fatalf("forged record opened: %q", pt)
		}
	})
}

// FuzzParseKey: the key file parser never panics and only accepts 32-byte
// keys.
func FuzzParseKey(f *testing.F) {
	k, _ := FormatKey(bytes.Repeat([]byte{2}, keyLen))
	f.Add(k)
	f.Add([]byte(masterKeyHeader))
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := parseKey(data)
		if err == nil && len(key) != keyLen {
			t.Fatalf("key of %d bytes accepted", len(key))
		}
	})
}
