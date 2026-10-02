package core

import (
	"bytes"
	"errors"
	"sync"
)

// Bounds on what the SDK keeps of a scanner's output. A scanner pointed at a
// hostile target (a site answering every nuclei template with megabytes), or
// one that loops, must not be able to exhaust the sensor's memory: past the
// stdout bound the scan is stopped and fails, rather than being read without
// end or silently truncated into a "clean" result.
const (
	// DefaultMaxScannerOutput bounds a scanner's captured stdout (its
	// results) unless ExecConfig.MaxOutputBytes or
	// BaseScannerConfig.MaxOutputBytes sets another bound.
	DefaultMaxScannerOutput int64 = 512 << 20

	// maxScannerStderr bounds a scanner's captured stderr. Stderr only
	// explains a failure, so past the bound it is cut (and noted), not fatal.
	maxScannerStderr = 4 << 20
)

// ErrScannerOutputTooLarge reports a scanner stopped because its output
// exceeded the bound on captured output.
var ErrScannerOutputTooLarge = errors.New("scanner output exceeded the size limit")

// stderrTruncatedNote marks a cut stderr.
const stderrTruncatedNote = "\n[stderr truncated]\n"

// outputCapture is an io.Writer for a command's stdout or stderr. It keeps at
// most limit bytes, hands each complete line to onLine (when set), and calls
// onOverflow once when the output first goes past the limit; later writes
// are discarded (still reported as written, so the child is never blocked or
// handed an error by its own output). Lines are not limited by a token size:
// a single line of any length (a nuclei finding carrying a whole response)
// is delivered as long as it fits within limit.
type outputCapture struct {
	mu         sync.Mutex
	limit      int64
	buf        bytes.Buffer
	pending    []byte // the current, incomplete line (for onLine)
	onLine     func(line string)
	onOverflow func()
	overflowed bool
}

func newOutputCapture(limit int64, onLine func(string), onOverflow func()) *outputCapture {
	if limit <= 0 {
		limit = DefaultMaxScannerOutput
	}
	return &outputCapture{limit: limit, onLine: onLine, onOverflow: onOverflow}
}

func (c *outputCapture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if c.overflowed {
		return n, nil
	}
	if room := c.limit - int64(c.buf.Len()); int64(len(p)) > room {
		p = p[:room]
		c.overflowed = true
	}
	c.buf.Write(p)
	if c.onLine != nil {
		c.emitLines(p)
	}
	if c.overflowed && c.onOverflow != nil {
		c.onOverflow()
	}
	return n, nil
}

// emitLines hands every completed line in p (with what was pending) to
// onLine, without its line ending.
func (c *outputCapture) emitLines(p []byte) {
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			c.pending = append(c.pending, p...)
			return
		}
		line := append(c.pending, p[:i]...)
		c.onLine(string(bytes.TrimSuffix(line, []byte{'\r'})))
		c.pending = c.pending[:0]
		p = p[i+1:]
	}
}

// finish delivers a last line that had no line ending.
func (c *outputCapture) finish() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.onLine != nil && len(c.pending) > 0 {
		c.onLine(string(bytes.TrimSuffix(c.pending, []byte{'\r'})))
		c.pending = nil
	}
}

// Bytes returns the captured output.
func (c *outputCapture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Bytes()
}

// Overflowed reports whether the output went past the limit.
func (c *outputCapture) Overflowed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.overflowed
}

// stderrBytes returns captured stderr, noting a cut.
func (c *outputCapture) stderrBytes() []byte {
	b := c.Bytes()
	if c.Overflowed() {
		return append(append([]byte(nil), b...), stderrTruncatedNote...)
	}
	return b
}
