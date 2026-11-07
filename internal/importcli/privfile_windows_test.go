//go:build windows

package importcli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// assertPrivate checks the Windows form of mode 0600: a protected DACL with
// exactly the current user and SYSTEM, nothing inherited.
func assertPrivate(t *testing.T, path string, _ os.FileInfo) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	want, err := privateSDDL()
	if err != nil {
		t.Fatal(err)
	}
	got := sd.String()
	// The string form may add flags (AI, AR) after "D:P"; the entries must
	// be exactly ours.
	if !strings.HasPrefix(got, "D:P") || entries(got) != entries(want) {
		t.Fatalf("%s: DACL %s, want %s", path, got, want)
	}
}

func entries(sddl string) string {
	if i := strings.Index(sddl, "("); i >= 0 {
		return sddl[i:]
	}
	return ""
}

func TestWriteFile_TightensAnExistingFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	assertPrivate(t, p, nil)
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Fatalf("content %q", b)
	}
}
