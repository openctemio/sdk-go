package harness

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Fence wraps untrusted text (bundle fields, tool output) in a block tagged
// with a per-run random nonce, so the model can tell data from instructions
// and text cannot close the block early. It is a signal to the model, not a
// security boundary: the boundary is the grant, the policy and the closed
// output schema.
type Fence struct{ nonce string }

// NewFence makes a fence with a fresh nonce.
func NewFence() Fence {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("harness: no randomness: " + err.Error())
	}
	return Fence{nonce: hex.EncodeToString(b)}
}

// FenceWithNonce makes a fence with a given nonce: only for replaying a
// recorded run, whose start event holds the nonce.
func FenceWithNonce(nonce string) Fence { return Fence{nonce: nonce} }

// Nonce is the run's fence nonce (written to the run record).
func (f Fence) Nonce() string { return f.nonce }

// Wrap fences one labeled value. label is a field name or tool:<n>, never
// untrusted text.
func (f Fence) Wrap(label, text string) string {
	clean := Neutralize(text)
	// The nonce cannot appear inside: strip any occurrence, so text cannot
	// forge a closing tag for this run.
	clean = strings.ReplaceAll(clean, f.nonce, "")
	var b strings.Builder
	b.WriteString(`<untrusted ref="`)
	b.WriteString(label)
	b.WriteString(`" nonce="`)
	b.WriteString(f.nonce)
	b.WriteString("\">\n")
	b.WriteString(clean)
	b.WriteString("\n</untrusted nonce=\"")
	b.WriteString(f.nonce)
	b.WriteString("\">")
	return b.String()
}

// Neutralize normalizes untrusted text: drops invalid UTF-8, zero-width and
// bidirectional control characters and other non-printing format characters
// that hide instructions from a human reviewer, and keeps newlines and tabs.
func Neutralize(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "")
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\t':
			return r
		}
		if unicode.Is(unicode.Cf, r) || (unicode.IsControl(r) && r != '\r') {
			return -1
		}
		return r
	}, s)
}

// Truncate caps s at max bytes on a rune boundary and says so.
func Truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "\n[truncated]"
}
