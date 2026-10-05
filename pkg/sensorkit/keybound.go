package sensorkit

// A key-bound sensor (api RFC-052): no API key; the sensor holds its own
// Ed25519 key in <state dir>/identity and signs every request with it. A
// sensor started with neither an API key nor an identity pairs on first
// start: it prints a code and a fingerprint, an administrator compares the
// fingerprint and approves, and the sensor continues with its new identity.

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/sensorkit/identity"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// checkCAPinHost warns when SENSOR_CA_FINGERPRINT is set but API_URL names
// the platform by an IP address: a pinned connection needs a host name to
// check the certificate against (httpsec.ErrPinnedCANoServerName), so every
// platform request would fail.
func (k *Kit) checkCAPinHost() {
	if len(httpsec.APIPinnedCA()) == 0 || !PinnedURLHasIPHost(k.s.apiURL) {
		return
	}
	msg := EnvCAFingerprint + " is set but " + EnvAPIURL + " uses an IP address; a pinned platform CA needs a host name " +
		"(the name in the platform certificate), so platform requests will fail"
	_, _ = fmt.Fprintf(k.errw, "WARNING: %s\n", msg)
	k.ReportCheck(core.ConfigCheck{ID: CheckCAPinHost, Status: core.CheckWarn, Code: "ip_url_with_pin",
		Params: map[string]core.ConfigParam{"name": core.ParamName(EnvAPIURL)}, Summary: msg})
}

// PinnedURLHasIPHost reports whether rawURL names its host by an IP
// address (which a pinned platform CA cannot be checked against).
func PinnedURLHasIPHost(rawURL string) bool {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	_, err = netip.ParseAddr(u.Hostname())
	return err == nil
}

// validCAFingerprint validates SENSOR_CA_FINGERPRINT.
func validCAFingerprint(v string) error {
	_, err := httpsec.ParseCAFingerprint(v)
	return err
}

// resolveIdentity loads the sensor's paired identity, or pairs when it has
// none and no API key (not even one renewed into the state directory).
// It leaves s.signer nil when the sensor should use a bearer key.
func (k *Kit) resolveIdentity() error {
	s := &k.s
	store := identity.NewStore(s.stateDir)
	id, signer, err := store.Load()
	switch {
	case err == nil:
		k.useIdentity(id, signer)
		if id.PlatformURL != "" && strings.TrimRight(id.PlatformURL, "/") != strings.TrimRight(s.apiURL, "/") {
			_, _ = fmt.Fprintf(k.errw, "WARNING: this sensor was paired with %s but %s is %s; the platform must still know its key\n",
				id.PlatformURL, EnvAPIURL, s.apiURL)
		}
		return nil
	case !errors.Is(err, identity.ErrNoIdentity):
		// A key or identity file with loose permissions, another owner, or
		// a mismatch: refuse to start (RFC-052 D-7) with the fix.
		return usageError(err)
	}
	// No identity. A key renewed into the state directory by an earlier
	// bearer-key run still counts as a configured key.
	if sk, err := resolveStartKey(k.opts.CredentialsFile, s.stateDir, "", s.sensorID, "false"); err == nil && sk.key != "" {
		return nil
	}
	if !s.commands {
		return nil
	}
	if k.opts.NoAutoPair {
		return usageError(fmt.Errorf("the sensor has no API key and is not paired: run `openctemio-sensor pair`, " +
			"or set API_KEY"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	name := firstNonEmpty(k.opts.Name, os.Getenv(EnvSensorName))
	_, _ = fmt.Fprintf(k.errw, "This sensor has no identity yet; pairing with %s (identity in %s).\n", s.apiURL, store.Dir())
	id, err = identity.Pair(ctx, identity.PairOptions{
		BaseURL:        s.apiURL,
		Store:          store,
		Host:           identity.DefaultHostFacts(k.opts.ProductName, k.opts.Version, name),
		PlatformKeyPin: envOr(k.opts.PlatformKey, EnvPlatformKey),
		Retry:          true,
		Out:            k.errw,
		UserAgent:      productToken(k.opts.ProductName, k.opts.Version),
	})
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	_, signer, err = store.Load()
	if err != nil {
		return err
	}
	k.useIdentity(id, signer)
	return nil
}

func (k *Kit) useIdentity(id *identity.Identity, signer *sensorsig.Signer) {
	s := &k.s
	s.signer = signer
	s.identity = id
	s.sensorID = id.SensorID
	if k.opts.Name == "" && os.Getenv(EnvSensorName) == "" && id.Name != "" {
		k.opts.Name = id.Name
	}
	_, _ = fmt.Fprintf(k.out, "  Identity: key-bound sensor %s (key SHA256:%s)\n", id.SensorID, id.KeyID)
}

func productToken(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "/" + version
}
