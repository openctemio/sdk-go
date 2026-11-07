package identity

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

var errStopTest = errors.New("test: stop waiting")

// research/468 D8: a refused enrollment token keeps the daemon up with a
// hold kept in the state directory; a restart within the hold waits the
// rest of it and makes no platform call.
func TestPairHoldSurvivesARestart(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.refuseToken = true
	var out bytes.Buffer
	o := opts(t, srv, &out)
	o.RetryTransient, o.HoldOnStop, o.EnrollmentToken = true, true, "octe_example_token"
	var waits []time.Duration
	o.sleep = func(_ context.Context, d time.Duration) error { waits = append(waits, d); return errStopTest }
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrEnrollmentRefused) {
		t.Fatalf("err %v, want the refusal once the wait is canceled", err)
	}
	if f.starts != 1 || len(waits) != 1 || waits[0] < holdMin-time.Minute || waits[0] > holdMin {
		t.Fatalf("starts %d, waits %v: want one start and a %s hold", f.starts, waits, holdMin)
	}
	h, err := o.Store.LoadHold()
	if err != nil || h == nil || h.Stops != 1 || !strings.Contains(h.Reason, "enrollment token") {
		t.Fatalf("hold %+v %v", h, err)
	}
	b, _ := os.ReadFile(filepath.Join(o.Store.Dir(), HoldFile))
	if strings.Contains(string(b), o.EnrollmentToken) {
		t.Fatalf("the hold file carries the token: %s", b)
	}
	if fi, err := os.Stat(filepath.Join(o.Store.Dir(), HoldFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("hold file mode %v %v", fi, err)
	}

	// The restart: same state directory and token.
	requests := f.starts + f.preHellos
	waits = nil
	if _, err := Pair(context.Background(), o); !errors.Is(err, errStopTest) {
		t.Fatalf("restart: %v, want the hold wait", err)
	}
	if f.starts+f.preHellos != requests {
		t.Fatalf("a restart within the hold called the platform (%d requests, had %d)", f.starts+f.preHellos, requests)
	}
	if len(waits) != 1 || waits[0] > holdMin || waits[0] < holdMin-time.Minute || !strings.Contains(out.String(), "on hold until") {
		t.Fatalf("waits %v, output:\n%s", waits, out.String())
	}

	// A new token ends the hold at once.
	f.refuseToken, f.instance = false, true
	o.EnrollmentToken = "octe_example_token_2"
	o.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := Pair(context.Background(), o); err != nil {
		t.Fatalf("new token: %v", err)
	}
	if h, _ := o.Store.LoadHold(); h != nil {
		t.Fatalf("a paired sensor keeps a hold: %+v", h)
	}
}

// Stops in a row double the hold, up to the cap.
func TestNextHoldDoubles(t *testing.T) {
	now := time.Now()
	var h *Hold
	for _, want := range []time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 2 * time.Hour, 4 * time.Hour, 6 * time.Hour, 6 * time.Hour} {
		h = nextHold(h, "x", now, "r")
		if got := h.Until.Sub(now); got != want {
			t.Fatalf("stop %d: hold %s, want %s", h.Stops, got, want)
		}
	}
	if h = nextHold(h, "other", now, "r"); h.Stops != 1 {
		t.Fatalf("new settings restart the count: %+v", h)
	}
}

// SECURITY: an answer without the platform's signed grant is still refused
// with the hold on, and nothing is saved: the daemon stays up and holds.
func TestPairHoldUnsignedAnswerSavesNothing(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.noGrant = true
	o := opts(t, srv, &bytes.Buffer{})
	o.RetryTransient, o.HoldOnStop = true, true
	o.sleep = func(_ context.Context, d time.Duration) error {
		if d >= holdMin-time.Minute {
			return errStopTest
		}
		return nil
	}
	_, err := Pair(context.Background(), o)
	if !errors.Is(err, pairing.ErrGrantMissing) {
		t.Fatalf("err %v, want the unsigned answer refused", err)
	}
	if _, _, lerr := o.Store.Load(); !errors.Is(lerr, ErrNoIdentity) {
		t.Fatalf("an unsigned answer saved an identity: %v", lerr)
	}
	if f.confirmed {
		t.Fatal("the sensor confirmed an unsigned approval")
	}
	if h, _ := o.Store.LoadHold(); h == nil || !strings.Contains(h.Reason, pairing.ProblemAnswerUnsigned) {
		t.Fatalf("hold %+v", h)
	}
}

// research/468 D9: a platform whose hello says it does not sign pairing
// answers is refused before any pairing request starts, with the versions
// named; one that lists the feature, or serves hello only to paired
// sensors, pairs.
func TestPairChecksPlatformCapabilities(t *testing.T) {
	f, srv := newFakePlatform(t)
	f.publicHello = []string{protov2.FeatureHeartbeat}
	_, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{}))
	if !errors.Is(err, ErrPlatformUnsignedPairing) || f.starts != 0 {
		t.Fatalf("err %v starts %d: want the refusal before any start", err, f.starts)
	}
	for _, want := range []string{pairing.MinPlatformSignedGrant, protov2.FeaturePairingAnswerSigned} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("message lacks %q: %v", want, err)
		}
	}

	for name, features := range map[string][]string{
		"advertised":        {protov2.FeatureHeartbeat, protov2.FeaturePairingAnswerSigned},
		"hello needs a key": nil,
	} {
		f, srv := newFakePlatform(t)
		f.publicHello = features
		if _, err := Pair(context.Background(), opts(t, srv, &bytes.Buffer{})); err != nil || f.preHellos != 1 {
			t.Fatalf("%s: %v, hellos %d", name, err, f.preHellos)
		}
	}

	// The daemon holds instead of exiting.
	f, srv = newFakePlatform(t)
	f.publicHello = []string{protov2.FeatureHeartbeat}
	o := opts(t, srv, &bytes.Buffer{})
	o.RetryTransient, o.HoldOnStop = true, true
	o.sleep = func(context.Context, time.Duration) error { return errStopTest }
	if _, err := Pair(context.Background(), o); !errors.Is(err, ErrPlatformUnsignedPairing) || f.starts != 0 {
		t.Fatalf("daemon: %v, starts %d", err, f.starts)
	}
	if h, _ := o.Store.LoadHold(); h == nil {
		t.Fatal("no hold kept")
	}
}
