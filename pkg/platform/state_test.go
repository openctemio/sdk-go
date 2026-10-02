package platform

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	installedKey = "rda_installed0000000000000000000000000000000000000000000000000000"
	renewedKey   = "rda_renewed00000000000000000000000000000000000000000000000000000"
	adminNewKey  = "rda_regenerated000000000000000000000000000000000000000000000000"
)

func TestChooseAPIKey(t *testing.T) {
	exp := time.Now().Add(90 * 24 * time.Hour).UTC().Truncate(time.Second)

	write := func(t *testing.T, creds *SensorCredentials) *FileCredentialStore {
		t.Helper()
		store := NewFileCredentialStore(filepath.Join(t.TempDir(), "sensor-credentials.json"))
		if creds != nil {
			if err := store.Save(creds); err != nil {
				t.Fatal(err)
			}
		}
		return store
	}

	t.Run("no file: the configured key", func(t *testing.T) {
		c := ChooseAPIKey(write(t, nil), installedKey, "")
		if c.APIKey != installedKey || c.FromStateFile {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("a renewal saved by RotatedKeySaver wins over the configured key", func(t *testing.T) {
		store := write(t, nil)
		if err := RotatedKeySaver(store, installedKey, "")(renewedKey, &exp); err != nil {
			t.Fatal(err)
		}
		c := ChooseAPIKey(store, installedKey, "")
		if c.APIKey != renewedKey || !c.FromStateFile || c.ExpiresAt == nil || !c.ExpiresAt.Equal(exp) || c.NeverExpires {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("a renewal without expiry is remembered as never expiring", func(t *testing.T) {
		store := write(t, nil)
		_ = RotatedKeySaver(store, installedKey, "")(renewedKey, nil)
		c := ChooseAPIKey(store, installedKey, "")
		if c.APIKey != renewedKey || !c.NeverExpires || c.ExpiresAt != nil {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("the operator configured a regenerated key: it wins", func(t *testing.T) {
		store := write(t, nil)
		_ = RotatedKeySaver(store, installedKey, "")(renewedKey, &exp)
		c := ChooseAPIKey(store, adminNewKey, "")
		if c.APIKey != adminNewKey || c.FromStateFile {
			t.Fatalf("a newly configured key must win over a file renewed from another key: %+v", c)
		}
	})
	t.Run("a file from before fingerprints: its key wins, as before", func(t *testing.T) {
		store := write(t, &SensorCredentials{APIKey: renewedKey, ExpiresAt: &exp})
		if c := ChooseAPIKey(store, installedKey, ""); c.APIKey != renewedKey {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("the same key in both: configured, with the file's expiry", func(t *testing.T) {
		store := write(t, &SensorCredentials{APIKey: installedKey, ExpiresAt: &exp})
		c := ChooseAPIKey(store, installedKey, "")
		if c.APIKey != installedKey || c.FromStateFile || c.ExpiresAt == nil {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("another sensor's file is ignored", func(t *testing.T) {
		store := write(t, &SensorCredentials{SensorID: "other", APIKey: renewedKey})
		if c := ChooseAPIKey(store, installedKey, "me"); c.APIKey != installedKey {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("no configured key: the file's key", func(t *testing.T) {
		store := write(t, &SensorCredentials{APIKey: renewedKey})
		if c := ChooseAPIKey(store, "", ""); c.APIKey != renewedKey {
			t.Fatalf("%+v", c)
		}
	})
	t.Run("a corrupt file: the configured key", func(t *testing.T) {
		store := write(t, nil)
		if err := os.WriteFile(store.Path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if c := ChooseAPIKey(store, installedKey, ""); c.APIKey != installedKey {
			t.Fatalf("%+v", c)
		}
	})
}

func TestRotatedKeySaver_FileIs0600AndHoldsNoConfiguredKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store := NewFileCredentialStore(StateCredentialsFile(dir))
	if err := RotatedKeySaver(store, installedKey, "sid")(renewedKey, nil); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, want 0600", st.Mode().Perm())
	}
	dst, _ := os.Stat(dir)
	if dst.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode = %v, want 0700", dst.Mode().Perm())
	}
	raw, _ := os.ReadFile(store.Path)
	if strings.Contains(string(raw), installedKey) {
		t.Fatal("the configured key itself must never be written, only its fingerprint")
	}
	if !strings.Contains(string(raw), renewedKey) || !strings.Contains(string(raw), `"configured_key_fingerprint"`) || !strings.Contains(string(raw), `"pbkdf2-sha256$`) {
		t.Fatalf("file: %s", raw)
	}
	saved, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if match, ok := KeyFingerprintMatches(saved.ConfiguredKeyFingerprint, installedKey); !ok || !match {
		t.Fatalf("the saved fingerprint does not match the installed key (match %v, ok %v)", match, ok)
	}
}

func TestResolveStateDir(t *testing.T) {
	t.Setenv(EnvStateDir, "")
	if got := ResolveStateDir("/explicit"); got != "/explicit" {
		t.Fatalf("explicit: %q", got)
	}
	t.Setenv(EnvStateDir, "/from/env")
	if got := ResolveStateDir(""); got != "/from/env" {
		t.Fatalf("env: %q", got)
	}
}

func TestResolveStateCredentialsFile_MovesTheHomeFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := filepath.Join(home, ".openctem", "sensor-credentials.json")
	// Written by an older sensor daemon: a renewed key, no sensor id.
	if err := NewFileCredentialStore(old).Save(&SensorCredentials{APIKey: renewedKey}); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	got, err := ResolveStateCredentialsFile("", state)
	if err != nil {
		t.Fatal(err)
	}
	if got != StateCredentialsFile(state) {
		t.Fatalf("file = %q, want the state directory's", got)
	}
	creds, err := NewFileCredentialStore(got).Load()
	if err != nil || creds.APIKey != renewedKey {
		t.Fatalf("the renewed key must move with the file: %v %+v", err, creds)
	}
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatal("the old file must be gone after the move")
	}

	// Explicit path: returned as is.
	if got, _ := ResolveStateCredentialsFile("/x/creds.json", state); got != "/x/creds.json" {
		t.Fatalf("explicit: %q", got)
	}
}

func TestResolveStateCredentialsFile_UnusableHomeFileIsIgnored(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	old := filepath.Join(home, ".openctem", "sensor-credentials.json")
	if err := os.MkdirAll(filepath.Dir(old), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(old, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	got, err := ResolveStateCredentialsFile("", state)
	if err != nil || got != StateCredentialsFile(state) {
		t.Fatalf("got %q, %v", got, err)
	}
}

func withMountInfo(t *testing.T, inContainer bool, table string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mountinfo")
	if err := os.WriteFile(path, []byte(table), 0o600); err != nil {
		t.Fatal(err)
	}
	prevPath, prevFn := mountInfoPath, inContainerFunc
	mountInfoPath = path
	inContainerFunc = func() bool { return inContainer }
	t.Cleanup(func() { mountInfoPath, inContainerFunc = prevPath, prevFn })
}

const dockerMountInfo = `1001 1000 0:52 / / rw,relatime - overlay overlay rw,lowerdir=/x
1002 1001 0:55 / /proc rw - proc proc rw
1010 1001 253:1 /var/lib/docker/volumes/s-outbox/_data /var/lib/openctem/outbox rw,relatime - ext4 /dev/vda1 rw
1011 1001 253:1 /var/lib/docker/volumes/s-state/_data /var/lib/openctem/state rw,relatime - ext4 /dev/vda1 rw
1012 1001 0:60 / /run/tmp rw - tmpfs tmpfs rw
1013 1001 253:1 /data /mnt/with\040space rw - ext4 /dev/vda1 rw
`

func TestCheckStatePersistence(t *testing.T) {
	withMountInfo(t, true, dockerMountInfo)
	cases := []struct {
		dir  string
		want bool
	}{
		{"/var/lib/openctem/state", true},
		{"/var/lib/openctem/state/sub", true},
		{"/var/lib/openctem/outbox", true},
		{"/var/lib/openctem", false},          // the container's own layer
		{"/var/lib/openctem/statefoo", false}, // a prefix is not a mount
		{"/run/tmp/state", false},             // tmpfs
		{"/mnt/with space/state", true},       // escaped mount point
	}
	for _, c := range cases {
		if got := CheckStatePersistence(c.dir); got.Persistent != c.want {
			t.Errorf("%s: persistent=%v (%s), want %v", c.dir, got.Persistent, got.Reason, c.want)
		}
	}

	withMountInfo(t, false, "")
	if !CheckStatePersistence("/anything").Persistent {
		t.Fatal("outside a container the host filesystem persists")
	}

	withMountInfo(t, true, "garbage")
	if CheckStatePersistence("/var/lib/openctem/state").Persistent {
		t.Fatal("an unreadable mount table in a container must not count as persistent")
	}
}

func TestDecideKeyAutoRenew(t *testing.T) {
	persistent := StatePersistence{Persistent: true, Reason: "volume"}
	ephemeral := StatePersistence{Reason: "no volume"}
	cases := []struct {
		setting string
		p       StatePersistence
		want    bool
	}{
		{"true", ephemeral, true},
		{"on", ephemeral, true},
		{"false", persistent, false},
		{"0", persistent, false},
		{"", persistent, true},
		{"auto", persistent, true},
		{"", ephemeral, false},
		{"AUTO", ephemeral, false},
	}
	for _, c := range cases {
		if got, why := DecideKeyAutoRenew(c.setting, c.p); got != c.want || why == "" {
			t.Errorf("DecideKeyAutoRenew(%q, %v) = %v (%q), want %v", c.setting, c.p.Persistent, got, why, c.want)
		}
	}
}

func TestUnescapeMount(t *testing.T) {
	if got := unescapeMount(`/a\040b\011c`); got != "/a b\tc" {
		t.Fatalf("%q", got)
	}
	if got := unescapeMount(`/plain`); got != "/plain" {
		t.Fatalf("%q", got)
	}
}

func TestKeyFingerprint(t *testing.T) {
	a, b := KeyFingerprint("rda_one"), KeyFingerprint("rda_one")
	if a == b {
		t.Fatal("each fingerprint has its own salt")
	}
	if !strings.HasPrefix(a, "pbkdf2-sha256$600000$") {
		t.Fatalf("format %q", a)
	}
	if m, ok := KeyFingerprintMatches(a, "rda_one"); !ok || !m {
		t.Fatalf("same key: match %v ok %v", m, ok)
	}
	if m, ok := KeyFingerprintMatches(a, "rda_two"); !ok || m {
		t.Fatalf("other key: match %v ok %v", m, ok)
	}
	// Not a fingerprint this SDK can check: unknown, not "different".
	for _, fp := range []string{"", "abc", strings.Repeat("a", 64), "pbkdf2-sha256$x$a$b", "md5$1$AA$AA"} {
		if _, ok := KeyFingerprintMatches(fp, "rda_one"); ok {
			t.Errorf("%q accepted as a fingerprint", fp)
		}
	}
}

// A changed configured key wins; an unreadable fingerprint keeps the file's key.
func TestConfiguredKeyChanged(t *testing.T) {
	fp := KeyFingerprint("rda_installed")
	if configuredKeyChanged(fp, "rda_installed") {
		t.Error("same key reported as changed")
	}
	if !configuredKeyChanged(fp, "rda_regenerated") {
		t.Error("regenerated key not detected")
	}
	if configuredKeyChanged("", "rda_any") || configuredKeyChanged("deadbeef", "rda_any") {
		t.Error("an unknown fingerprint must not count as a change")
	}
}
