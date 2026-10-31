package identity

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
)

const repairSensorID = "11111111-2222-3333-4444-555555555555"

func keyRegisteredReply() func(http.ResponseWriter) {
	return problemReply(409, "pairing-key-registered", "Key already registered", "this key belongs to a sensor")
}

// interrupt runs Pair until its first wait for approval, then cancels it
// (a Ctrl-C), as an operator would.
func interrupt(t *testing.T, o PairOptions) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.sleep = func(context.Context, time.Duration) error { cancel(); return ctx.Err() }
	if _, err := Pair(ctx, o); !errors.Is(err, context.Canceled) {
		t.Fatalf("interrupted pairing: %v", err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(path string) bool { _, err := os.Lstat(path); return err == nil }

// A key the platform says is registered, with no identity ever confirmed,
// never became active: it is replaced once, and pairing starts again.
func TestPairKeyRegisteredWithoutIdentityRotatesOnce(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){keyRegisteredReply()}
	var out bytes.Buffer
	o := opts(t, srv, &out)
	old, err := o.Store.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	_, sg, err := o.Store.Load()
	if err != nil || sg.KeyID() == old.KeyID() || f.starts != 2 {
		t.Fatalf("key replaced=%v starts=%d err=%v", sg.KeyID() != old.KeyID(), f.starts, err)
	}
	if !strings.Contains(out.String(), "This sensor's key was already registered by an approval that was never confirmed; generated a new key.") {
		t.Fatalf("output:\n%s", out.String())
	}
	// Only once: a second answer of the same kind is not rotated again.
	f2, srv2 := newFakePlatform(t)
	f2.startReplies = []func(http.ResponseWriter){keyRegisteredReply(), keyRegisteredReply()}
	o2 := opts(t, srv2, &bytes.Buffer{})
	if _, err := Pair(context.Background(), o2); !errors.Is(err, ErrKeyRegistered) || f2.starts != 2 {
		t.Fatalf("second refusal: %v starts=%d", err, f2.starts)
	}
}

// With a confirmed identity the key is or was in use: never replaced. The CLI
// exits with the explanation; the daemon waits instead of exiting.
func TestPairKeyRegisteredWithIdentityStops(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.startReplies = []func(http.ResponseWriter){keyRegisteredReply(), keyRegisteredReply()}
	o := opts(t, srv, &bytes.Buffer{})
	sg, err := o.Store.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Store.Save(&Identity{SensorID: repairSensorID, KeyID: sg.KeyID()}); err != nil {
		t.Fatal(err)
	}
	keyBefore := readFile(t, filepath.Join(o.Store.Dir(), KeyFile))
	_, err = Pair(context.Background(), o)
	if !errors.Is(err, ErrKeyRegistered) || !strings.Contains(err.Error(), "Re-pair it (Sensors > sensor > Re-pair)") || f.starts != 1 {
		t.Fatalf("CLI: %v starts=%d", err, f.starts)
	}
	// Daemon: waits at least 5 minutes, says why once, keeps the key.
	var out bytes.Buffer
	d := opts(t, srv, &out)
	d.Store = o.Store
	d.RetryTransient = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var sleeps []time.Duration
	d.sleep = func(_ context.Context, w time.Duration) error {
		sleeps = append(sleeps, w)
		if len(sleeps) == 2 {
			cancel()
		}
		return nil
	}
	f.startReplies = []func(http.ResponseWriter){keyRegisteredReply(), keyRegisteredReply(), keyRegisteredReply()}
	_, err = Pair(ctx, d)
	if err == nil || len(sleeps) != 2 || sleeps[0] < 5*time.Minute || sleeps[1] < 5*time.Minute {
		t.Fatalf("daemon: err=%v sleeps=%v", err, sleeps)
	}
	if n := strings.Count(out.String(), "already registered"); n != 1 {
		t.Fatalf("explained %d times:\n%s", n, out.String())
	}
	if !bytes.Equal(keyBefore, readFile(t, filepath.Join(o.Store.Dir(), KeyFile))) {
		t.Fatal("the key of a confirmed identity was replaced")
	}
}

// A code spent by a request that expired is never sent again: the daemon
// continues without a code and says so; the CLI exits.
func TestPairSpentCodeIsNeverResent(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.finalStatus = pairing.StatusExpired
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.Retry = true
	o.Code, o.CodeLabel = "k7qm-4ztd", "SENSOR_PAIRING_CODE"
	o.sleep = func(context.Context, time.Duration) error {
		if f.starts >= 2 {
			f.finalStatus = pairing.StatusApproved
		}
		return nil
	}
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	// The codeless request expired too (the fake switches at its first
	// poll); every request after the first carries no code.
	if len(f.codes) < 2 || f.codes[0] != "K7QM4ZTD" || f.codes[1] != "" || f.codes[len(f.codes)-1] != "" {
		t.Fatalf("codes sent: %q", f.codes)
	}
	for _, want := range []string{"The pairing code K7QM… expired (or was refused); it is single use. Starting a request without a code:", "K7QM-4ZTD"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "K7QM4ZTD") || strings.Contains(out.String(), "4ZTD\n") && strings.Contains(out.String(), "pairing code K7QM4") {
		t.Fatalf("the code leaked:\n%s", out.String())
	}
}

func TestPairSpentCodeDeniedAndCLI(t *testing.T) {
	for _, status := range []string{pairing.StatusDenied, pairing.StatusExpired} {
		f, srv := newFakePlatform(t)
		f.finalStatus = status
		o := opts(t, srv, &bytes.Buffer{})
		o.Code = "k7qm-4ztd"
		_, err := Pair(context.Background(), o)
		want := ErrExpired
		if status == pairing.StatusDenied {
			want = ErrDenied
		}
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "single use") || strings.Contains(err.Error(), "K7QM4ZTD") || f.starts != 1 {
			t.Fatalf("%s: err=%v starts=%d", status, err, f.starts)
		}
	}
	// The daemon continues without a code after a denial too.
	f, srv := newFakePlatform(t)
	f.finalStatus = pairing.StatusDenied
	o := opts(t, srv, &bytes.Buffer{})
	o.Retry, o.Code = true, "k7qm-4ztd"
	// The denial of the request with the code falls back to a codeless
	// request, whose own denial is final.
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrDenied) || len(f.codes) != 2 || f.codes[1] != "" {
		t.Fatalf("err=%v codes=%q", err, f.codes)
	}
}

// A restart after the administrator approved but before the sensor
// confirmed picks the approved request up: it confirms, it starts nothing.
func TestPairResumesAnApprovedRequestAfterARestart(t *testing.T) {
	f, srv := newFakePlatform(t)
	o := opts(t, srv, &bytes.Buffer{})
	interrupt(t, o)
	if f.confirmed || f.starts != 1 || !exists(filepath.Join(o.Store.Dir(), PairingFile)) {
		t.Fatalf("after the interrupt: confirmed=%v starts=%d", f.confirmed, f.starts)
	}
	fi, _ := os.Stat(filepath.Join(o.Store.Dir(), PairingFile))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("pairing.json mode %v", fi.Mode().Perm())
	}
	if strings.Contains(string(readFile(t, filepath.Join(o.Store.Dir(), PairingFile))), "PRIVATE") {
		t.Fatal("pairing.json holds key material")
	}
	var out bytes.Buffer
	o.Out = &out
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !f.confirmed || f.starts != 1 {
		t.Fatalf("confirmed=%v starts=%d (a new request was started)", f.confirmed, f.starts)
	}
	if !strings.Contains(out.String(), "Resuming") || !strings.Contains(out.String(), f.sas.String()) {
		t.Fatalf("output:\n%s", out.String())
	}
	if exists(filepath.Join(o.Store.Dir(), PairingFile)) {
		t.Fatal("pairing.json left after the pairing completed")
	}
	if _, _, err := o.Store.Load(); err != nil {
		t.Fatal(err)
	}
}

// A request still waiting is resumed: the fingerprint is printed again and
// polling continues, with no new request.
func TestPairResumesAPendingRequestAndReprintsTheFingerprint(t *testing.T) {
	f, srv := newFakePlatform(t)
	o := opts(t, srv, &bytes.Buffer{})
	interrupt(t, o)
	f.status = pairing.StatusPending
	var out bytes.Buffer
	o.Out = &out
	if _, err := Pair(context.Background(), o); err != nil || f.starts != 1 {
		t.Fatalf("err=%v starts=%d", err, f.starts)
	}
	if !strings.Contains(out.String(), "K7QM-4ZTD") || !strings.Contains(out.String(), f.sas.String()) {
		t.Fatalf("output:\n%s", out.String())
	}
}

// An expired, purged or refused request is dropped and a new one starts.
func TestPairResumeOfAGoneRequestStartsFresh(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone func(f *fakePlatform)
	}{
		{"expired", func(f *fakePlatform) { f.status = pairing.StatusExpired }},
		{"denied", func(f *fakePlatform) { f.status = pairing.StatusDenied }},
		{"purged", func(f *fakePlatform) { f.revealed = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			o := opts(t, srv, &bytes.Buffer{})
			interrupt(t, o)
			tc.gone(f)
			if _, err := Pair(context.Background(), o); err != nil {
				t.Fatal(err)
			}
			if f.starts != 2 || !f.confirmed {
				t.Fatalf("starts=%d confirmed=%v", f.starts, f.confirmed)
			}
		})
	}
}

// A saved request that expired long ago is not even asked about.
func TestPairResumeIgnoresARequestExpiredBeyondTheConfirmWindow(t *testing.T) {
	f, srv := newFakePlatform(t)
	o := opts(t, srv, &bytes.Buffer{})
	interrupt(t, o)
	p, err := o.Store.LoadPending()
	if err != nil || p == nil {
		t.Fatal(err)
	}
	p.ExpiresAt = time.Now().Add(-pairConfirmWindow - time.Minute)
	if err := o.Store.SavePending(p); err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(context.Background(), o); err != nil || f.starts != 2 {
		t.Fatalf("err=%v starts=%d", err, f.starts)
	}
}

// A new code configured after the interrupted request supersedes it, and a
// spent code is not resent by a restart whose environment still holds it.
func TestPairResumeAndCodes(t *testing.T) {
	f, srv := newFakePlatform(t)
	o := opts(t, srv, &bytes.Buffer{})
	interrupt(t, o) // a request without a code
	o.Code = "k7qm-4ztd"
	if _, err := Pair(context.Background(), o); err != nil || f.starts != 2 || f.codes[1] != "K7QM4ZTD" {
		t.Fatalf("a new code: err=%v starts=%d codes=%q", err, f.starts, f.codes)
	}

	// The code's request expires; the daemon falls back to a codeless one
	// that is then interrupted. A restart with the same code in its
	// environment resumes that request instead of sending the spent code.
	f, srv = newFakePlatform(t)
	f.finalStatus = pairing.StatusExpired
	o = opts(t, srv, &bytes.Buffer{})
	o.Retry, o.Code = true, "k7qm-4ztd"
	ctx, cancel := context.WithCancel(context.Background())
	o.sleep = func(context.Context, time.Duration) error {
		if f.starts == 2 {
			cancel()
			return ctx.Err()
		}
		return nil
	}
	if _, err := Pair(ctx, o); !errors.Is(err, context.Canceled) || len(f.codes) != 2 {
		t.Fatalf("err=%v codes=%q", err, f.codes)
	}
	cancel()
	f.status = pairing.StatusPending
	f.finalStatus = pairing.StatusApproved
	o.sleep = func(context.Context, time.Duration) error { return nil }
	o.Code = "k7qm-4ztd"
	if _, err := Pair(context.Background(), o); err != nil || len(f.codes) != 2 {
		t.Fatalf("restart: err=%v codes=%q", err, f.codes)
	}
}

// A re-pair that is interrupted, refused or expired leaves the working key
// and identity as they were.
func TestRepairInterruptedLeavesTheWorkingIdentity(t *testing.T) {
	for _, tc := range []string{"interrupt", "denied", "expired"} {
		t.Run(tc, func(t *testing.T) {
			f, srv := newFakePlatform(t)
			o := opts(t, srv, &bytes.Buffer{})
			o.NewKey, o.RepairSensorID = true, repairSensorID
			sg, err := o.Store.EnsureKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := o.Store.Save(&Identity{SensorID: repairSensorID, TenantID: "t", KeyID: sg.KeyID()}); err != nil {
				t.Fatal(err)
			}
			keyPath, idPath := filepath.Join(o.Store.Dir(), KeyFile), filepath.Join(o.Store.Dir(), IdentityFile)
			key0, id0 := readFile(t, keyPath), readFile(t, idPath)
			switch tc {
			case "interrupt":
				interrupt(t, o)
			case "denied":
				f.finalStatus = pairing.StatusDenied
				if _, err := Pair(context.Background(), o); !errors.Is(err, ErrDenied) {
					t.Fatal(err)
				}
			case "expired":
				f.finalStatus = pairing.StatusExpired
				if _, err := Pair(context.Background(), o); !errors.Is(err, ErrExpired) {
					t.Fatal(err)
				}
			}
			if !bytes.Equal(key0, readFile(t, keyPath)) || !bytes.Equal(id0, readFile(t, idPath)) {
				t.Fatal("the working key or identity changed")
			}
			if _, _, err := o.Store.Load(); err != nil {
				t.Fatalf("the old identity no longer loads: %v", err)
			}
			if !exists(filepath.Join(o.Store.Dir(), NextKeyFile)) && tc == "interrupt" {
				t.Fatal("no staged key after the interrupt")
			}
		})
	}
}

// A later re-pair reuses the staged key and its request instead of making
// another; success swaps the key and the identity together.
func TestRepairReusesTheStagedKeyAndSwapsOnSuccess(t *testing.T) {
	f, srv := newFakePlatform(t)
	o := opts(t, srv, &bytes.Buffer{})
	o.NewKey, o.RepairSensorID = true, repairSensorID
	old, err := o.Store.EnsureKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Store.Save(&Identity{SensorID: repairSensorID, TenantID: "t", KeyID: old.KeyID()}); err != nil {
		t.Fatal(err)
	}
	interrupt(t, o)
	nextPath := filepath.Join(o.Store.Dir(), NextKeyFile)
	staged := readFile(t, nextPath)
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if f.starts != 1 || !f.confirmed {
		t.Fatalf("starts=%d confirmed=%v (the staged request was not reused)", f.starts, f.confirmed)
	}
	if exists(nextPath) || exists(filepath.Join(o.Store.Dir(), PairingFile)) {
		t.Fatal("staging files left after the swap")
	}
	if !bytes.Equal(staged, readFile(t, filepath.Join(o.Store.Dir(), KeyFile))) {
		t.Fatal("signing.key is not the staged key")
	}
	id, sg, err := o.Store.Load()
	if err != nil || sg.KeyID() == old.KeyID() || id.KeyID != sg.KeyID() || id.SensorID != repairSensorID {
		t.Fatalf("after the swap: %v %+v", err, id)
	}
}

// A crash between writing the identity and the key swap is healed by Load.
func TestLoadFinishesAnInterruptedPromotion(t *testing.T) {
	s := NewStore(t.TempDir())
	if _, err := s.EnsureKey(); err != nil {
		t.Fatal(err)
	}
	next, err := s.RotateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(&Identity{SensorID: repairSensorID, KeyID: next.KeyID()}); err != nil {
		t.Fatal(err)
	}
	_, sg, err := s.Load()
	if err != nil || sg.KeyID() != next.KeyID() || exists(filepath.Join(s.Dir(), NextKeyFile)) {
		t.Fatalf("load: %v", err)
	}
}

// The staged key and the pending request are held to the same permission
// rules as the key and the identity.
func TestStoreChecksTheStagingFiles(t *testing.T) {
	for _, name := range []string{NextKeyFile, PairingFile} {
		s := NewStore(t.TempDir())
		if _, err := s.EnsureKey(); err != nil {
			t.Fatal(err)
		}
		if _, err := s.RotateKey(); err != nil {
			t.Fatal(err)
		}
		if err := s.SavePending(&Pending{PairingID: pid, KeyID: "k", PlatformKey: "p"}); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(s.Dir(), name)
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		var pe *PermissionError
		if err := s.Check(); !errors.As(err, &pe) || pe.Fix != "chmod 0600 "+path {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
