package sensorkit

// Self-binding (api docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4.8): a daemon that starts with an API key, against a platform whose
// hello lists the key_bind feature, makes its own Ed25519 key in
// <state dir>/identity, binds it with one call authenticated by the API key,
// and signs every request from then on. The platform retires the API key in
// the same step, so the move is one way; an identity in the state directory
// wins over a configured API_KEY at every later start.
//
// The key and a marker are on disk before the call. If the answer is lost,
// the next start binds the same key again, or (the API key already retired)
// confirms it with a request signed by that key. A refusal (the
// organization requires an administrator's approval, or the sensor cannot
// bind) removes the generated key and the sensor keeps its API key.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// EnvKeyBind turns self-binding off ("off"); unset or "auto" binds when
// the platform offers it.
const EnvKeyBind = "SENSOR_KEY_BIND"

// keyBindTimeout bounds the whole bind at start.
const keyBindTimeout = 30 * time.Second

// keyBindEnabled reads SENSOR_KEY_BIND.
func keyBindEnabled() (bool, error) {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(EnvKeyBind))) {
	case "", "auto", "on", "true":
		return true, nil
	case "off", "false":
		return false, nil
	default:
		return false, usageError(fmt.Errorf("%s=%q is not one of auto, off", EnvKeyBind, os.Getenv(EnvKeyBind)))
	}
}

// preferIdentity makes a sensor that has an identity sign with it even when
// API_KEY is still configured (the API key was retired by a bind or a
// re-pair). Returns whether an identity is in use.
func (k *Kit) preferIdentity() (bool, error) {
	s := &k.s
	store := identity.NewStore(s.stateDir)
	id, signer, err := store.Load()
	switch {
	case errors.Is(err, identity.ErrNoIdentity):
		return false, nil
	case err != nil:
		return false, usageError(err)
	}
	if err := k.useIdentity(id, signer); err != nil {
		return false, err
	}
	_, _ = fmt.Fprintf(k.errw, "Warning: %s is ignored: this sensor is key-bound (identity in %s); remove %s from its configuration\n",
		EnvAPIKey, store.Dir(), EnvAPIKey)
	s.apiKey = ""
	return true, nil
}

// autoBindKey binds a signing key for a bearer-key daemon when the platform
// offers it. Failures never stop the sensor: it keeps its API key and tries
// again at its next start.
func (k *Kit) autoBindKey(protocol string) {
	s := &k.s
	on, err := keyBindEnabled()
	if err != nil || !on || s.apiKey == "" || s.signer != nil || s.apiURL == "" {
		return
	}
	store := identity.NewStore(s.stateDir)
	ctx, cancel := context.WithTimeout(context.Background(), keyBindTimeout)
	defer cancel()
	bearer := client.New(&client.Config{BaseURL: s.apiURL, APIKey: s.apiKey, SensorID: s.sensorID,
		Timeout: k.opts.Timeout, Protocol: protocol})
	defer func() { _ = bearer.Close() }()

	pending := store.BindPending()
	if !pending {
		hello, err := bearer.Hello(ctx)
		if err != nil || !hello.Supports(protov2.FeatureKeyBind) {
			return
		}
	}
	signer, err := store.EnsureKey()
	if err != nil {
		_, _ = fmt.Fprintf(k.errw, "Warning: key bind skipped: %v\n", err)
		return
	}
	if err := store.MarkBindPending(); err != nil {
		_, _ = fmt.Fprintf(k.errw, "Warning: key bind skipped: %v\n", err)
		return
	}
	res, err := bearer.BindKey(ctx, signer)
	var ve *client.V2Error
	if errors.As(err, &ve) && ve.Status == http.StatusUnauthorized && pending {
		// The API key is gone: an earlier bind of this key may have been
		// applied without its answer arriving. Confirm with the key itself.
		signed := client.New(&client.Config{BaseURL: s.apiURL, Signer: signer, SensorID: s.sensorID,
			Timeout: k.opts.Timeout, Protocol: protocol})
		res, err = signed.BindKey(ctx, signer)
		_ = signed.Close()
	}
	if err != nil {
		k.keyBindFailed(store, err)
		return
	}
	id := &identity.Identity{PlatformURL: s.apiURL, SensorID: res.SensorID, TenantID: res.TenantID, Name: res.Name,
		KeyID: signer.KeyID(), PairedAt: time.Now().UTC()}
	if err := store.Save(id); err != nil {
		// The platform bound the key; the marker stays, so the next start
		// confirms it and writes the identity.
		_, _ = fmt.Fprintf(k.errw, "Warning: the key is bound but the identity could not be saved (%v); the next start confirms it\n", err)
		k.useBound(id, signer)
		return
	}
	store.ClearBindPending()
	k.useBound(id, signer)
	_, _ = fmt.Fprintf(k.errw, "This sensor is now key-bound: it signs its requests with its own key (SHA256:%s in %s); "+
		"its API key is retired, remove %s from its configuration\n", signer.KeyID(), store.Dir(), EnvAPIKey)
}

func (k *Kit) useBound(id *identity.Identity, signer *sensorsig.Signer) {
	_ = k.useIdentity(id, signer) // a bound identity carries no TLS pin
	k.s.apiKey = ""
}

// keyBindFailed keeps the API key. A refusal removes the generated key; any
// other failure keeps it for the next start.
func (k *Kit) keyBindFailed(store *identity.Store, err error) {
	var ve *client.V2Error
	if !errors.As(err, &ve) || ve.Transient() {
		_, _ = fmt.Fprintf(k.errw, "Warning: key bind did not complete (%v); the sensor keeps its API key and tries again at its next start\n", err)
		return
	}
	store.DiscardBind()
	switch ve.ProblemName() {
	case protov2.ProblemKeyBindApproval:
		_, _ = fmt.Fprintf(k.errw, "Key bind refused: the organization requires an administrator to approve this sensor's key; "+
			"the sensor keeps its API key (re-pair it with `pair -repair` to move it to a key-bound identity)\n")
	default:
		_, _ = fmt.Fprintf(k.errw, "Warning: key bind refused (%v); the sensor keeps its API key\n", err)
	}
}
