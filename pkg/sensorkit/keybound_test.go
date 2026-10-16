package sensorkit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/conformance"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
)

func pairedStore(t *testing.T, dir string) *identity.Identity {
	t.Helper()
	st := identity.NewStore(dir)
	sg, err := st.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	id := &identity.Identity{SensorID: "11111111-2222-3333-4444-555555555555", TenantID: "t", Name: "paired-01",
		KeyID: sg.KeyID(), PairedAt: time.Now()}
	if err := st.Save(id); err != nil {
		t.Fatal(err)
	}
	return id
}

// A paired sensor needs no API key: its client signs every request.
func TestNew_KeyBoundIdentity(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, out, _ := baseOptions(t, f)
	opts.APIKey = ""
	id := pairedStore(t, opts.StateDir)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.closeClient)
	if k.Client() == nil || !k.Client().KeyBound() || k.s.sensorID != id.SensorID || k.s.apiKey != "" {
		t.Fatalf("client key-bound=%v sensor=%q key=%q", k.Client() != nil && k.Client().KeyBound(), k.s.sensorID, k.s.apiKey)
	}
	if !strings.Contains(out.String(), "key-bound sensor "+id.SensorID) {
		t.Fatalf("stdout: %s", out.String())
	}
	if k.s.key.autoRenew {
		t.Fatal("a key-bound sensor has no bearer key to renew")
	}
}

// RFC-052 D-7: a key readable by others stops the sensor with the fix.
func TestNew_KeyBoundRefusesLoosePermissions(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	opts.APIKey = ""
	pairedStore(t, opts.StateDir)
	key := filepath.Join(opts.StateDir, identity.DirName, identity.KeyFile)
	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	_, err := New(opts)
	var pe *identity.PermissionError
	if !errors.As(err, &pe) || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "chmod 0600 "+key) {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
}

// Without a key, an identity or auto-pairing, the sensor says how to pair.
func TestNew_NoKeyNoAutoPair(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	opts.APIKey = ""
	opts.NoAutoPair = true
	_, err := New(opts)
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "openctemio-sensor pair") {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
}

func TestNew_CAFingerprint(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	t.Cleanup(func() { httpsec.SetAPIPinnedCA(nil) })
	opts, _, errw := baseOptions(t, f)
	t.Setenv(EnvCAFingerprint, "not-hex")
	if _, err := New(opts); err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), EnvCAFingerprint) {
		t.Fatalf("bad fingerprint: %v", err)
	}
	t.Setenv(EnvCAFingerprint, "SHA256:"+strings.Repeat("ab", 32))
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	k.closeClient()
	if len(httpsec.APIPinnedCA()) != 32 {
		t.Fatal("the pin was not set")
	}
	// The fake platform listens on 127.0.0.1: an IP URL with a pin is
	// warned about (the pinned connection needs a host name).
	if !strings.Contains(errw.String(), "uses an IP address") {
		t.Fatalf("no IP-URL warning: %s", errw.String())
	}
	if PinnedURLHasIPHost("https://platform.example") || !PinnedURLHasIPHost("https://[::1]:8443") {
		t.Fatal("PinnedURLHasIPHost")
	}
}

// SENSOR_PAIRING_CODE: a malformed code stops a sensor with no identity,
// and the error never echoes the value.
func TestNew_PairingCodeMalformedRefused(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, errw := baseOptions(t, f)
	opts.APIKey = ""
	const bad = "SECRET-NOT-A-CODE"
	t.Setenv(EnvPairingCode, bad)
	_, err := New(opts)
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), EnvPairingCode) {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	if strings.Contains(err.Error(), bad) || strings.Contains(errw.String(), bad) {
		t.Fatalf("the code leaked: err=%v stderr=%s", err, errw.String())
	}
}

// A well-formed code passes validation (NoAutoPair then stops the start
// before any request), and it is never printed.
func TestNew_PairingCodeValidAccepted(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.APIKey = ""
	opts.NoAutoPair = true
	t.Setenv(EnvPairingCode, "k7qm-4ztd")
	_, err := New(opts)
	if err == nil || !strings.Contains(err.Error(), "openctemio-sensor pair") {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{out.String(), errw.String()} {
		if strings.Contains(strings.ToUpper(s), "K7QM") {
			t.Fatalf("the code was printed: %s", s)
		}
	}
}

// Once the sensor is paired, the code is ignored (with a note), even a
// malformed one, and never printed.
func TestNew_PairingCodeIgnoredOncePaired(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.APIKey = ""
	pairedStore(t, opts.StateDir)
	t.Setenv(EnvPairingCode, "K7QM-4ZTD")
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.closeClient)
	if !strings.Contains(errw.String(), EnvPairingCode+" is ignored: the sensor is already paired") {
		t.Fatalf("stderr: %s", errw.String())
	}
	if strings.Contains(out.String()+errw.String(), "K7QM") {
		t.Fatal("the code was printed")
	}
}

// A sensor with an API key does not pair: the code is ignored with a note.
func TestNew_PairingCodeIgnoredWithAPIKey(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, errw := baseOptions(t, f)
	t.Setenv(EnvPairingCode, "K7QM-4ZTD")
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.closeClient)
	if !strings.Contains(errw.String(), EnvPairingCode+" is ignored") {
		t.Fatalf("stderr: %s", errw.String())
	}
}

// SENSOR_INSTANCE_ENROLLMENT_TOKEN (api RFC-100 §7): a malformed token
// stops a sensor with no identity, the error never echoes the value, and it
// cannot be combined with SENSOR_PAIRING_CODE.
func TestNew_InstanceEnrollmentTokenMalformedRefused(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, errw := baseOptions(t, f)
	opts.APIKey = ""
	const bad = "octe_SECRETSECRET"
	t.Setenv(EnvInstanceEnrollmentToken, bad)
	_, err := New(opts)
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), EnvInstanceEnrollmentToken) {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
	if strings.Contains(err.Error(), bad) || strings.Contains(errw.String(), bad) {
		t.Fatalf("the token leaked: err=%v stderr=%s", err, errw.String())
	}
}

func TestNew_InstanceEnrollmentTokenWithPairingCodeRefused(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, _, _ := baseOptions(t, f)
	opts.APIKey = ""
	t.Setenv(EnvPairingCode, "K7QM-4ZTD")
	t.Setenv(EnvInstanceEnrollmentToken, "octe_"+strings.Repeat("a", 49))
	_, err := New(opts)
	if err == nil || ExitCode(err) != ExitUsage || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("err = %v (exit %d)", err, ExitCode(err))
	}
}

// Once the sensor is paired, the token is ignored (with a note) and never
// printed.
func TestNew_InstanceEnrollmentTokenIgnoredOncePaired(t *testing.T) {
	f := conformance.NewFakePlatform(true)
	t.Cleanup(f.Close)
	opts, out, errw := baseOptions(t, f)
	opts.APIKey = ""
	pairedStore(t, opts.StateDir)
	tok := "octe_" + strings.Repeat("Z", 49)
	t.Setenv(EnvInstanceEnrollmentToken, tok)
	k, err := New(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.closeClient)
	if !strings.Contains(errw.String(), EnvInstanceEnrollmentToken+" is ignored: the sensor is already paired") {
		t.Fatalf("stderr: %s", errw.String())
	}
	if strings.Contains(out.String()+errw.String(), tok) {
		t.Fatal("the token was printed")
	}
}
