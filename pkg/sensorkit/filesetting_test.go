package sensorkit

import (
	"bytes"
	"crypto/ed25519"
	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSettingValueFile(t *testing.T) {
	const name = "SENSOR_TEST_SETTING"
	dir := t.TempDir()
	good := writeFile(t, dir, "good", "  value-1\n", 0o644)

	t.Setenv(name+"_FILE", good)
	v, fromFile, err := settingValue("", name)
	if err != nil || v != "value-1" || !fromFile {
		t.Fatalf("got %q %v %v", v, fromFile, err)
	}

	// both the variable and the file: refused, without echoing either value
	t.Setenv(name, "secret-env")
	_, _, err = settingValue("", name)
	if err == nil || !strings.Contains(err.Error(), "not both") || strings.Contains(err.Error(), "secret-env") || strings.Contains(err.Error(), "value-1") {
		t.Fatalf("want a not-both error, got %v", err)
	}
	// a programmatic option counts as the variable
	t.Setenv(name, "")
	if _, _, err = settingValue("opt", name); err == nil {
		t.Fatal("option plus file must be refused")
	}

	// only the variable
	t.Setenv(name+"_FILE", "")
	t.Setenv(name, " plain ")
	if v, fromFile, err = settingValue("", name); err != nil || v != "plain" || fromFile {
		t.Fatalf("got %q %v %v", v, fromFile, err)
	}
}

func TestReadSettingFileRefusals(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"group-writable": writeFile(t, dir, "gw", "x", 0o664),
		"world-writable": writeFile(t, dir, "ww", "x", 0o666),
		"empty":          writeFile(t, dir, "empty", " \n", 0o644),
		"too-big":        writeFile(t, dir, "big", strings.Repeat("a", maxSettingFile+1), 0o644),
		"missing":        filepath.Join(dir, "nope"),
		"directory":      dir,
	}
	for name, p := range cases {
		if _, err := readSettingFile(p); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	if _, err := readSettingFile(writeFile(t, dir, "ro", "ok", 0o400)); err != nil {
		t.Errorf("0400 must be accepted: %v", err)
	}
}

func TestReadSettingFileSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "mnt")
	other := filepath.Join(root, "other")
	for _, d := range []string{dir, other} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	outside := writeFile(t, other, "v", "outside", 0o644)
	if err := os.Symlink(outside, filepath.Join(dir, "escape")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if _, err := readSettingFile(filepath.Join(dir, "escape")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("symlink leaving the directory must be refused, got %v", err)
	}
	// a container secret layout: file -> ..data/file, ..data -> ..ts, all inside
	writeSub := filepath.Join(dir, "..ts")
	if err := os.Mkdir(writeSub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, writeSub, "tok", "inside", 0o644)
	if err := os.Symlink("..ts", filepath.Join(dir, "..data")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..data", "tok"), filepath.Join(dir, "tok")); err != nil {
		t.Fatal(err)
	}
	if v, err := readSettingFile(filepath.Join(dir, "tok")); err != nil || v != "inside" {
		t.Fatalf("in-directory symlink chain: %q %v", v, err)
	}
}

func TestInstanceEnrollmentTokenFile(t *testing.T) {
	tok := "octe_" + strings.Repeat("a", 49)
	p := writeFile(t, t.TempDir(), "token", tok+"\n", 0o600)
	t.Setenv(EnvInstanceEnrollmentToken, "")
	t.Setenv(EnvInstanceEnrollmentTokenFile, p)
	got, err := instanceEnrollmentToken()
	if err != nil || got != tok {
		t.Fatalf("got %q %v", got, err)
	}
	bad := writeFile(t, t.TempDir(), "token", "not-a-token", 0o600)
	t.Setenv(EnvInstanceEnrollmentTokenFile, bad)
	if _, err = instanceEnrollmentToken(); err == nil || strings.Contains(err.Error(), "not-a-token") {
		t.Fatalf("malformed token must be refused without echoing it: %v", err)
	}
}

// A pin from a file is exclusive: what pairing took from the platform on
// first use (keys and a root a compromised platform could have served) is
// not trusted next to it. A key pin from the environment stays additive.
func TestNew_JobSigningPinFileIsExclusive(t *testing.T) {
	tofu := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey))
	pin := jobsig.NewPublicKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)).Public().(ed25519.PublicKey))
	tofuRoot := "SHA256:" + strings.Repeat("ab", 32)
	for _, tc := range []struct {
		name       string
		file       bool
		wantTOFU   bool
		wantRootID string
	}{
		{name: "file", file: true, wantTOFU: false, wantRootID: ""},
		{name: "env", file: false, wantTOFU: true, wantRootID: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Cleanup(func() { core.SetJobsPosture(""); core.SetJobsKeySet(nil) })
			f := conformance.NewFakePlatform(true)
			t.Cleanup(f.Close)
			opts, out, errw := baseOptions(t, f)
			opts.APIKey = ""
			pairedStore(t, opts.StateDir)
			st := identity.NewStore(opts.StateDir)
			id, _, err := st.Load()
			if err != nil {
				t.Fatal(err)
			}
			id.JobSigningKeys = []jobsig.PublicKey{tofu}
			if tc.file {
				id.JobSigningRoot = tofuRoot // with an env pin and a root, the root's key set replaces the keys anyway
			}
			if err := st.Save(id); err != nil {
				t.Fatal(err)
			}
			if tc.file {
				t.Setenv(EnvJobSigningKeysFile, writeFile(t, t.TempDir(), "keys", pin.PublicKey+"\n", 0o644))
			} else {
				t.Setenv(EnvJobSigningKeys, pin.PublicKey)
			}
			k, err := New(opts)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(k.closeClient)
			p := k.sensor.Posture()
			if p == nil || p.Jobs == nil {
				t.Fatal("no posture")
			}
			if p.Jobs.Root != tc.wantRootID {
				t.Fatalf("root %q, want %q", p.Jobs.Root, tc.wantRootID)
			}
			logs := out.String() + errw.String()
			if !strings.Contains(logs, pin.KeyID) {
				t.Fatalf("pinned key not in use:\n%s", logs)
			}
			if got := strings.Contains(logs, tofu.KeyID); got != tc.wantTOFU {
				t.Fatalf("TOFU key trusted = %v, want %v:\n%s", got, tc.wantTOFU, logs)
			}
		})
	}
}

// Both the variable and its _FILE form stop the sensor at start.
func TestNew_JobSigningPinBothRefused(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	opts.APIKey = ""
	pairedStore(t, opts.StateDir)
	t.Setenv(EnvJobSigningRoot, "SHA256:"+strings.Repeat("cd", 32))
	t.Setenv(EnvJobSigningRootFile, writeFile(t, t.TempDir(), "root", "SHA256:"+strings.Repeat("cd", 32), 0o644))
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("err = %v", err)
	}
}
