package core

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/openctemio/sdk-go/pkg/shared/fingerprint"
)

// The values below are made up and match no real token format, so secret
// scanners do not flag this file.

func TestMaskSecret_VisibleCharactersAreCapped(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", "****"},
		{"x", "****"},
		{"hunter2", "****"},
		{"short-one", "****"},
		{"elevenchars", "****"},          // 11: nothing shown
		{"not-a-real-1", "no****1"},      // 12: 3 of 12
		{"not-a-real-val", "no****l"},    // 14: 3 of 14
		{"fakevalue-01234x", "fa****4x"}, // 16: 4 of 16
		{"fake_tok_0123456789abcdefghijklmn", "fake****klmn"},
	}
	for _, tc := range cases {
		if got := MaskSecret(tc.in); got != tc.want {
			t.Errorf("MaskSecret(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// For every length, the visible characters are at most a quarter of the
// secret, at most 4 at either end, and none below 12 characters (CTIS spec
// 4.8 allows up to half; this stays well inside it).
func TestMaskSecret_NeverRevealsMoreThanAQuarter(t *testing.T) {
	for n := 0; n <= 200; n++ {
		secret := strings.Repeat("q", n)
		got := MaskSecret(secret)
		if !strings.Contains(got, secretMaskMarker) {
			t.Fatalf("n=%d: no mask marker in %q", n, got)
		}
		visible := utf8.RuneCountInString(got) - len(secretMaskMarker)
		if n < 12 && visible != 0 {
			t.Errorf("n=%d: %d characters shown of a short secret", n, visible)
		}
		if visible*4 > n {
			t.Errorf("n=%d: %d characters shown, more than a quarter", n, visible)
		}
		head, tail := secretVisibleEnds(n)
		if head > 4 || tail > 4 {
			t.Errorf("n=%d: %d/%d shown at the ends, more than 4", n, head, tail)
		}
	}
}

// The masked value has the same form whatever the secret's length beyond
// the visible ends: the length is not revealed.
func TestMaskSecret_DoesNotRevealLength(t *testing.T) {
	a := MaskSecret("abcd" + strings.Repeat("m", 40) + "wxyz")
	b := MaskSecret("abcd" + strings.Repeat("m", 400) + "wxyz")
	if a != b {
		t.Errorf("masked values differ by length: %q vs %q", a, b)
	}
}

func TestMaskSecret_CountsRunesNotBytes(t *testing.T) {
	secret := "ééééééééééééééééé" // 17 two-byte runes
	got := MaskSecret(secret)
	if !utf8.ValidString(got) {
		t.Fatalf("masking cut a multi-byte character: %q", got)
	}
	if got != "éé****éé" {
		t.Errorf("MaskSecret = %q, want %q", got, "éé****éé")
	}
}

func TestMaskSecretInText_ShortSecretFullyHidden(t *testing.T) {
	secret := "pw-fake-01" // 10 characters
	got := MaskSecretInText(`password = "`+secret+`"`, secret)
	if strings.Contains(got, "pw-") || strings.Contains(got, "-01") {
		t.Fatalf("part of a short secret survived: %q", got)
	}
	if got != `password = "****"` {
		t.Errorf("got %q", got)
	}
}

func TestMaskSecretInText_UnknownSecretHidesWholeText(t *testing.T) {
	if got := MaskSecretInText("token=fakevalue0123456789xyz", "absent"); got != secretMaskMarker {
		t.Errorf("text not shown to be free of the secret must be hidden, got %q", got)
	}
}

// The fingerprint never hashes the raw secret: two secrets with the same
// masked value at the same place get the same fingerprint, and the
// fingerprint equals the one built from the masked value.
func TestGenerateSecretFingerprint_UsesMaskedValue(t *testing.T) {
	const raw = "fake_tok_0123456789abcdefghijklmn"
	got := GenerateSecretFingerprint("app/config.yml", "generic-api-key", 7, raw)
	if want := fingerprint.GenerateSecret("app/config.yml", "generic-api-key", 7, MaskSecret(raw)); got != want {
		t.Fatalf("fingerprint is not built from the masked value")
	}
	if rawFP := fingerprint.GenerateSecret("app/config.yml", "generic-api-key", 7, raw); got == rawFP {
		t.Fatalf("fingerprint still hashes the raw secret")
	}
	// A short secret contributes nothing guessable: every short secret at
	// the same place has the same fingerprint.
	a := GenerateSecretFingerprint("a.env", "pw", 1, "pw-fake-01")
	b := GenerateSecretFingerprint("a.env", "pw", 1, "pw-fake-02")
	if a != b {
		t.Errorf("short secrets must not influence the fingerprint")
	}
}

func TestMaskAPIKey_SameCap(t *testing.T) {
	if got := MaskAPIKey("fake-key-01"); got != "****" {
		t.Errorf("MaskAPIKey(11 chars) = %q, want ****", got)
	}
	if got := MaskAPIKey("fake_tok_0123456789abcdefghijklmn"); got != "fake...klmn" {
		t.Errorf("MaskAPIKey = %q", got)
	}
}
