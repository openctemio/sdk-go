package sensorkit

// API-key auto-renewal for a daemon (RFC-014 Phase 2, api RFC-032 Phase 0):
// the key is renewed on schedule (half its lifetime) and at once when the
// heartbeat doorbell says rotate_key, swapped into every client that uses it
// and saved in the state directory for the next start (the renewal retired
// the configured key). Persistence is the SDK's (pkg/platform state.go):
// ResolveStateCredentialsFile, ChooseAPIKey, RotatedKeySaver,
// CheckStatePersistence, DecideKeyAutoRenew.

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/client"
	"github.com/openctemio/sdk-go/pkg/platform"
)

// statePersistence judges whether the state directory survives the sensor
// being recreated; replaceable in tests.
var statePersistence = platform.CheckStatePersistence

// startKey is the key a kit starts with, after the state directory was
// consulted, and the renewal decision.
type startKey struct {
	file          string // credentials file renewed keys are saved to
	configuredKey string // the key from Options / API_KEY
	key           string // the key to start with
	fromStateFile bool
	expiresAt     *time.Time
	neverExpires  bool
	autoRenew     bool
	why           string // the renewal decision, for the log
}

// resolveStartKey picks the credentials file in stateDir (explicit wins; a
// ~/.openctem file from an earlier version is moved there), the key to start
// with (a renewed key wins unless the configured key changed since,
// platform.ChooseAPIKey) and whether to renew (renewSetting "true"/"false",
// else only when the state persists, platform.DecideKeyAutoRenew).
func resolveStartKey(explicitFile, stateDir, configuredKey, sensorID, renewSetting string) (startKey, error) {
	file, err := platform.ResolveStateCredentialsFile(explicitFile, stateDir)
	if err != nil {
		return startKey{}, err
	}
	choice := platform.ChooseAPIKey(platform.NewFileCredentialStore(file), configuredKey, sensorID)
	sk := startKey{
		file: file, configuredKey: configuredKey, key: choice.APIKey,
		fromStateFile: choice.FromStateFile && choice.APIKey != configuredKey,
		expiresAt:     choice.ExpiresAt, neverExpires: choice.NeverExpires,
	}
	sk.autoRenew, sk.why = platform.DecideKeyAutoRenew(renewSetting, statePersistence(filepath.Dir(file)))
	return sk, nil
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

// keyRenewConfig saves each rotated key (platform.RotatedKeySaver: atomic,
// 0600, with its expiry and the configured key's fingerprint) and logs it.
func keyRenewConfig(sk startKey, sensorID string, verbose bool, w io.Writer) *platform.KeyRenewConfig {
	save := platform.RotatedKeySaver(platform.NewFileCredentialStore(sk.file), sk.configuredKey, sensorID)
	return &platform.KeyRenewConfig{
		Verbose:                verbose,
		CurrentKeyExpiresAt:    sk.expiresAt,
		CurrentKeyNeverExpires: sk.neverExpires,
		OnRotated: func(newKey string, exp *time.Time) error {
			if err := save(newKey, exp); err != nil {
				return err
			}
			_, _ = fmt.Fprintf(w, "[apikey] %s rotated key saved to %s\n", time.Now().Format(time.RFC3339), sk.file)
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
	m := platform.NewKeyRenewManager(renewer, keyRenewConfig(s.key, s.sensorID, s.verbose, w))
	if err := m.Start(ctx); err != nil {
		return nil, err
	}
	return m, nil
}
