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
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// validPairingCode validates SENSOR_PAIRING_CODE. The error never carries
// the value: the code attaches a key to the tenant until it is approved.
func validPairingCode(v string) error {
	if _, err := pairing.NormalizeCode(v); err != nil {
		return fmt.Errorf("%s is not a pairing code (XXXX-XXXX)", EnvPairingCode)
	}
	return nil
}

// pairingCode is SENSOR_PAIRING_CODE in canonical form ("" when unset).
// A malformed code stops the sensor rather than starting a pairing the
// administrator is not waiting for.
func pairingCode() (string, error) {
	v := strings.TrimSpace(os.Getenv(EnvPairingCode))
	if v == "" {
		return "", nil
	}
	c, err := pairing.NormalizeCode(v)
	if err != nil {
		return "", usageError(validPairingCode(v))
	}
	return c, nil
}

// notePairingCodeIgnored tells the operator SENSOR_PAIRING_CODE (or
// SENSOR_INSTANCE_ENROLLMENT_TOKEN) had no effect (the sensor already has
// credentials) so it can be removed.
func (k *Kit) notePairingCodeIgnored(why string) {
	for _, env := range []string{EnvPairingCode, EnvInstanceEnrollmentToken} {
		if strings.TrimSpace(os.Getenv(env)) == "" {
			continue
		}
		_, _ = fmt.Fprintf(k.errw, "Note: %s is ignored: %s; it can be removed from the configuration\n", env, why)
	}
}

// instanceEnrollmentToken is SENSOR_INSTANCE_ENROLLMENT_TOKEN ("" when
// unset). A value that is not octe_ and 49 letters or digits stops the
// sensor; the error never carries the value.
func instanceEnrollmentToken() (string, error) {
	v := strings.TrimSpace(os.Getenv(EnvInstanceEnrollmentToken))
	if v == "" {
		return "", nil
	}
	if !wellFormedEnrollmentToken(v) {
		return "", usageError(fmt.Errorf("%s is not an enrollment token (octe_ and 49 letters or digits)", EnvInstanceEnrollmentToken))
	}
	return v, nil
}

func wellFormedEnrollmentToken(v string) bool {
	body, ok := strings.CutPrefix(v, "octe_")
	if !ok || len(body) != 49 {
		return false
	}
	for _, c := range body {
		if (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// checkCAPinHost warns when SENSOR_CA_FINGERPRINT is set but SENSOR_API_URL names
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
		k.notePairingCodeIgnored("the sensor is already paired")
		if err := k.useIdentity(id, signer); err != nil {
			return err
		}
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
		k.notePairingCodeIgnored("the sensor has an API key")
		return nil
	}
	if !s.commands {
		k.notePairingCodeIgnored("platform commands are off, so the sensor does not pair")
		return nil
	}
	code, err := pairingCode()
	if err != nil {
		return err
	}
	token, err := instanceEnrollmentToken()
	if err != nil {
		return err
	}
	if token != "" && code != "" {
		return usageError(fmt.Errorf("set %s or %s, not both", EnvPairingCode, EnvInstanceEnrollmentToken))
	}
	if k.opts.NoAutoPair {
		return usageError(fmt.Errorf("the sensor has no API key and is not paired: run `openctemio-sensor pair`, " +
			"or set SENSOR_API_KEY"))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	name := firstNonEmpty(k.opts.Name, os.Getenv(EnvSensorName))
	_, _ = fmt.Fprintf(k.errw, "This sensor has no identity yet; pairing with %s (identity in %s).\n", s.apiURL, store.Dir())
	id, err = identity.Pair(ctx, identity.PairOptions{
		BaseURL:         s.apiURL,
		Store:           store,
		Code:            code,
		CodeLabel:       EnvPairingCode,
		EnrollmentToken: token,
		Host:            identity.DefaultHostFacts(k.opts.ProductName, k.opts.Version, name),
		PlatformKeyPin:  envOr(k.opts.PlatformKey, EnvPlatformKey),
		// A spent enrollment token cannot start another request.
		Retry:     token == "",
		Out:       k.errw,
		UserAgent: productToken(k.opts.ProductName, k.opts.Version),
	})
	if err != nil {
		return fmt.Errorf("pairing: %w", err)
	}
	_, signer, err = store.Load()
	if err != nil {
		return err
	}
	return k.useIdentity(id, signer)
}

func (k *Kit) useIdentity(id *identity.Identity, signer *sensorsig.Signer) error {
	s := &k.s
	s.signer = signer
	s.identity = id
	s.sensorID = id.SensorID
	if k.opts.Name == "" && os.Getenv(EnvSensorName) == "" && id.Name != "" {
		k.opts.Name = id.Name
	}
	_, _ = fmt.Fprintf(k.out, "  Identity: key-bound sensor %s (key SHA256:%s)\n", id.SensorID, id.KeyID)
	return k.applyTLSPin(id)
}

// applyTLSPin enforces the platform TLS pin stored at pairing on every
// platform client created from now on (api RFC-040 §11.4 Q10).
// SENSOR_CA_FINGERPRINT, applied before, wins. An identity without a pin
// (paired over plain http or by an older SDK) keeps trusting the trust
// store; a malformed pin stops the sensor.
func (k *Kit) applyTLSPin(id *identity.Identity) error {
	element, fp, err := id.TLSPin()
	if err != nil {
		return usageError(err)
	}
	switch {
	case len(httpsec.APIPinnedCA()) > 0:
		if fp != nil {
			_, _ = fmt.Fprintf(k.out, "  Platform TLS pin: %s (overrides the pin stored at pairing)\n", EnvCAFingerprint)
		}
	case fp == nil:
		_, _ = fmt.Fprintf(k.errw, "Warning: this sensor was paired without a platform TLS pin; it trusts any CA in the trust store for the platform. Re-pair, or set %s, to pin it\n", EnvCAFingerprint)
	case element == httpsec.PinElementCACert:
		httpsec.SetAPIPinnedCA(fp)
		_, _ = fmt.Fprintf(k.out, "  Platform TLS pin: %s (CA certificate, stored at pairing)\n", id.PlatformTLSPin)
	default:
		httpsec.SetAPIPinnedSPKI(fp)
		_, _ = fmt.Fprintf(k.out, "  Platform TLS pin: %s (trust anchor key, stored at pairing)\n", id.PlatformTLSPin)
	}
	return nil
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
