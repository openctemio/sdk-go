package upstream

import (
	"bufio"
	"bytes"
	"testing"
)

func FuzzReadConnectReply(f *testing.F) {
	for _, s := range []string{
		"HTTP/1.1 200 Connection established\r\n\r\n",
		"HTTP/1.0 407 Auth\r\nProxy-Authenticate: Basic\r\n\r\nbody",
		"HTTP/1.1 502\r\n\r\n",
		"HTTP/1.1 2000 x\r\n\r\n",
		"SSH-2.0\r\n",
		"",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReaderSize(bytes.NewReader(b), 4096)
		code, err := readConnectReply(br)
		if err == nil && (code < 100 || code > 599) {
			t.Fatalf("code %d accepted", code)
		}
		if consumed := len(b) - br.Buffered(); err == nil && consumed > maxReplyHeader+4096 {
			t.Fatalf("read %d bytes", consumed)
		}
	})
}

func FuzzReadSOCKSReply(f *testing.F) {
	for _, s := range [][]byte{
		{5, 0, 0, 1, 1, 2, 3, 4, 0, 80},
		{5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 187},
		{5, 0, 0, 3, 4, 'h', 'o', 's', 't', 0, 1},
		{5, 5, 0, 9},
		{4, 0},
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReader(bytes.NewReader(b))
		if _, err := readSOCKSReply(br); err == nil && len(b) < 6 {
			t.Fatalf("short reply %x accepted", b)
		}
	})
}

func TestReadConnectReplyBoundsTheHeader(t *testing.T) {
	big := "HTTP/1.1 200 OK\r\n" + "X: " + string(bytes.Repeat([]byte("a"), 9000)) + "\r\n\r\n"
	if _, err := readConnectReply(bufio.NewReader(bytes.NewReader([]byte(big)))); err == nil {
		t.Fatal("header over 8 KiB accepted")
	}
	for _, s := range []string{"HTTP/1.1 200 OK\r\n", "HTTP/2 200\r\n\r\n", "HTTP/1.1 20x\r\n\r\n", "HTTP/1.1 200x\r\n\r\n"} {
		if _, err := readConnectReply(bufio.NewReader(bytes.NewReader([]byte(s)))); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}
