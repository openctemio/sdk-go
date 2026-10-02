package sensorkit

// API-key auto-renewal for a daemon (RFC-014 Phase 2): the key is renewed on
// schedule (half its lifetime) and at once when the heartbeat doorbell says
// rotate_key, swapped into every client that uses it and kept in the
// credentials file for the next start (the configured key was revoked by the
// renewal).
//
// SEAM (api RFC-032 P0): the renewed key is kept with the SDK's existing
// credentials file (platform.ResolveCredentialsFile, FileCredentialStore).
// RFC-032 moves key persistence into the SDK's state directory with its own
// store; when that lands, loadRenewedKey and persistRenewedKey call it and
// nothing else in the kit changes. Do not grow persistence here.

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// renewedKey is a key an earlier run renewed and saved.
type renewedKey struct {
	file      string
	key       string // "" when the file holds none for this sensor
	expiresAt *time.Time
}

// loadRenewedKey picks the credentials file (explicit, else the SDK
// default; a pre-rename file is moved there) and returns the key it holds
// for sensorID, if any.
func loadRenewedKey(explicit, sensorID string) (renewedKey, error) {
	file, err := platform.ResolveCredentialsFile(explicit)
	if err != nil {
		return renewedKey{}, err
	}
	rk := renewedKey{file: file}
	store := platform.NewFileCredentialStore(file)
	if !store.Exists() {
		return rk, nil
	}
	creds, err := store.Load()
	if err != nil || creds == nil || creds.APIKey == "" {
		return rk, nil
	}
	if sensorID != "" && creds.SensorID != "" && creds.SensorID != sensorID {
		return rk, nil // another sensor's file
	}
	rk.key, rk.expiresAt = creds.APIKey, creds.ExpiresAt
	return rk, nil
}

// persistRenewedKey saves a rotated key with its expiry for the next start.
func persistRenewedKey(file, sensorID, newKey string, exp *time.Time) error {
	prefix := newKey
	if len(prefix) > 12 {
		prefix = prefix[:12]
	}
	return platform.NewFileCredentialStore(file).Save(&platform.SensorCredentials{
		SensorID:  sensorID,
		APIKey:    newKey,
		APIPrefix: prefix,
		ExpiresAt: exp,
	})
}

// keyRenewer renews the API key and swaps the new key into every client
// that uses it.
type keyRenewer struct {
	renew *platform.PlatformClient // RenewKey only: POST /api/v2/sensor/keys (v1 renew on an older platform)
	api   *client.Client           // heartbeat, poll, ingest
}

func (r *keyRenewer) RenewKey(ctx context.Context) (*platform.RenewKeyResponse, error) {
	return r.renew.RenewKey(ctx)
}

func (r *keyRenewer) SetAPIKey(key string) {
	r.renew.SetAPIKey(key)
	r.api.SetAPIKey(key)
}

// keyRenewConfig persists each rotated key, with its expiry, and logs it.
func keyRenewConfig(file, sensorID string, expiresAt *time.Time, verbose bool, w io.Writer) *platform.KeyRenewConfig {
	return &platform.KeyRenewConfig{
		Verbose:             verbose,
		CurrentKeyExpiresAt: expiresAt,
		OnRotated: func(newKey string, exp *time.Time) error {
			if err := persistRenewedKey(file, sensorID, newKey, exp); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(w, "[apikey] %s rotated key saved to the credentials file\n", time.Now().Format(time.RFC3339))
			return nil
		},
	}
}

// startKeyRenewal starts key auto-renewal.
func startKeyRenewal(ctx context.Context, s *settings, api *client.Client, w io.Writer) (*platform.KeyRenewManager, error) {
	renewer := &keyRenewer{
		renew: platform.NewPlatformClient(&platform.ClientConfig{
			BaseURL:  s.apiURL,
			APIKey:   s.apiKey,
			SensorID: s.sensorID,
		}),
		api: api,
	}
	m := platform.NewKeyRenewManager(renewer, keyRenewConfig(s.credentialsFile, s.sensorID, s.keyExpiresAt, s.verbose, w))
	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
