package identity

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/jobsig"
	"github.com/openctemio/sdk-go/pkg/sensorproto/pairing"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
	"github.com/openctemio/sdk-go/pkg/useragent"
)

var (
	// ErrDenied: an administrator refused the pairing.
	ErrDenied = errors.New("pairing: an administrator refused this sensor")
	// ErrExpired: the pairing request expired before it was approved and
	// confirmed (and PairOptions.Retry was off).
	ErrExpired = errors.New("pairing: the request expired before it was approved")
	// ErrEnrollmentRefused: the platform refused the enrollment token
	// (malformed, unknown, expired, used up or revoked; it does not say
	// which). Ask whoever issued it for a new one.
	ErrEnrollmentRefused = errors.New("pairing: the platform refused the enrollment token (unknown, expired, used up or revoked)")
)

// ClockSkewError is the platform refusing a request because its signature
// time and the platform's clock differ by more than the tolerance (2
// minutes): this machine's clock or the platform's is wrong.
type ClockSkewError struct {
	// Offset is this machine's clock minus the platform's (positive: this
	// machine is ahead).
	Offset time.Duration
}

func (e *ClockSkewError) Error() string {
	d, dir := e.Offset, "ahead of"
	if d < 0 {
		d, dir = -d, "behind"
	}
	return fmt.Sprintf("pairing: the platform refused the request signature: this machine's clock is %s %s the platform's clock "+
		"(signatures allow %s). One of the two clocks is wrong: fix NTP on it (`timedatectl` shows the state, "+
		"`sudo chronyc makestep` steps the clock now)", d.Round(time.Second), dir, sensorsig.MaxClockSkew)
}

// Backoff of RetryTransient.
const (
	pairBackoffMin = 5 * time.Second
	pairBackoffMax = 5 * time.Minute
)

// PairOptions configures Pair.
type PairOptions struct {
	// BaseURL is the platform API URL (SENSOR_API_URL).
	BaseURL string
	// Store keeps the key and receives the identity.
	Store *Store
	// Code attaches to a pairing code an administrator created first
	// (reverse mode). Empty: the platform gives a code for the
	// administrator to enter.
	Code string
	// CodeLabel, when set, names where Code came from (an environment
	// variable); the instructions print it instead of the code, so a code
	// from the configuration never reaches the logs.
	CodeLabel string
	// EnrollmentToken is a single-use instance enrollment token (api
	// RFC-100 §7): the sensor is enrolled as a shared sensor (no
	// organization) without an administrator's approval, and the identity
	// must say so. Never with Code or RepairSensorID; Retry does not apply
	// (the token is spent by the first request).
	EnrollmentToken string
	// OrganizationEnrollment marks EnrollmentToken as an organization
	// enrollment token: the sensor joins the token's organization (the
	// identity must name one), and asking again with the same key spends
	// no use, so Retry applies.
	OrganizationEnrollment bool
	// RepairSensorID asks to re-pair this existing registration (lost or
	// stolen key); NewKey makes a fresh key first.
	RepairSensorID string
	NewKey         bool
	// Host describes this host to the administrator (DefaultHostFacts).
	Host pairing.HostFacts
	// PlatformKeyPin is the platform pairing key's thumbprint from the
	// install snippet (SENSOR_PLATFORM_KEY); a platform with another key is
	// refused. Empty: not pinned (the TLS pin and the SAS still apply).
	PlatformKeyPin string
	// JobSigningRoot is the job-signing root the console's install snippet
	// gives out of band (SENSOR_JOB_SIGNING_ROOT: "SHA256:<hex>" or the
	// base64 key). Set, the key set the platform serves must be signed by
	// it, or pairing fails before the identity is saved. This protects
	// against whatever sits between the sensor and the platform (a proxy,
	// a forged TLS chain the pin did not catch) and against a platform
	// compromised after the operator copied the snippet. It is not
	// independent of the platform itself: the console reads the root from
	// the platform's API, so a platform already compromised when the
	// snippet was copied can show its own root. For that case take the
	// root fingerprint from whoever holds the offline root key. Empty: the
	// root the platform's key set names is pinned on first use (TOFU).
	JobSigningRoot string
	// AllowUnsignedJobs is SENSOR_DANGEROUS_ALLOW_UNSIGNED_JOBS at pairing
	// (development only): the identity does not require signed jobs.
	// Without it, a new identity always requires them (RequireSignedJobs).
	AllowUnsignedJobs bool
	// Retry starts a new request when one expires (the daemon waits for an
	// administrator indefinitely); off, Pair returns ErrExpired.
	Retry bool
	// RetryTransient retries, in process, a pairing the platform refused for
	// a reason that can clear on its own or once an operator fixes it (a
	// clock skew, a rate limit, the platform unavailable, a network error),
	// with capped exponential backoff and a message each time, instead of
	// returning (a daemon that exits is restarted by its supervisor and
	// spends the platform's pairing budget in a loop). A refused enrollment
	// token, a denial or a platform key mismatch still returns.
	RetryTransient bool
	// Out receives the lines a person reads (the code, the fingerprint).
	Out io.Writer
	// HTTPClient sends the requests; it is wrapped to sign them. Default:
	// httpsec.NewAPIClientRecordingPin (SSRF guard, CA pin, no redirects),
	// which also learns the platform TLS pin the identity stores; with
	// another client only a SENSOR_CA_FINGERPRINT pin is stored.
	HTTPClient *http.Client
	// UserAgent is the product token ("openctemio-sensor/0.8.0").
	UserAgent string

	sleep func(context.Context, time.Duration) error
}

// DefaultHostFacts describes this host.
func DefaultHostFacts(product, version, name string) pairing.HostFacts {
	host, _ := os.Hostname()
	return pairing.HostFacts{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH, SensorVersion: version,
		SDKVersion: useragent.SDKVersion(), Product: product, Name: name}
}

// Pair runs interactive pairing (api RFC-052 §4.2) and saves the identity:
// start (signed with the sensor's key, committing to its nonce), check the
// platform's signature and pinned key, reveal the nonce, show the code and
// the fingerprint, wait for an administrator's approval, then confirm the
// identity with a signature. The private key never leaves the host.
func Pair(ctx context.Context, o PairOptions) (*Identity, error) {
	if o.Store == nil || o.BaseURL == "" {
		return nil, errors.New("pairing: BaseURL and Store are required")
	}
	if o.Out == nil {
		o.Out = os.Stderr
	}
	if o.sleep == nil {
		o.sleep = sleepCtx
	}
	if o.EnrollmentToken != "" && (o.Code != "" || o.RepairSensorID != "") {
		return nil, errors.New("pairing: an instance enrollment token cannot be combined with a pairing code or a re-pair")
	}
	if o.Code != "" {
		c, err := pairing.NormalizeCode(o.Code)
		if err != nil {
			return nil, err
		}
		o.Code = c
	}
	if w, err := httpsec.CheckAPIBaseURL(o.BaseURL); err != nil {
		return nil, fmt.Errorf("pairing: %w", err)
	} else if w != "" {
		_, _ = fmt.Fprintf(o.Out, "WARNING: %s\n", w)
	}
	var signer *sensorsig.Signer
	var err error
	if o.NewKey {
		signer, err = o.Store.RotateKey()
	} else {
		signer, err = o.Store.EnsureKey()
	}
	if err != nil {
		return nil, err
	}
	base := o.HTTPClient
	var rec *httpsec.PinRecorder
	if base == nil {
		// Every request of the pairing must lead to the CA the first one
		// verified; that CA's key becomes the stored pin.
		rec = &httpsec.PinRecorder{}
		base = httpsec.NewAPIClientRecordingPin(30*time.Second, rec)
	}
	hc := *base
	hc.Transport = &sensorsig.Transport{Signer: signer, Base: base.Transport, MaxBody: 64 << 10}
	pc := &pairClient{base: strings.TrimRight(o.BaseURL, "/") + protov2.PathPrefix, hc: &hc, ua: o.UserAgent, rec: rec}
	if _, err := jobsig.ParseRoot(o.JobSigningRoot); err != nil {
		return nil, fmt.Errorf("pairing: SENSOR_JOB_SIGNING_ROOT: %w", err)
	}

	backoff := pairBackoffMin
	for {
		id, err := pairOnce(ctx, pc, signer, o)
		switch {
		case err == nil:
			return id, nil
		case errors.Is(err, ErrExpired) && o.Retry && (o.EnrollmentToken == "" || o.OrganizationEnrollment):
			_, _ = fmt.Fprintln(o.Out, "The pairing request expired; starting a new one.")
			backoff = pairBackoffMin
			continue
		case o.RetryTransient && ctx.Err() == nil && transientPairError(err, o.EnrollmentToken != "" && !o.OrganizationEnrollment):
			_, _ = fmt.Fprintf(o.Out, "Pairing failed: %v\nRetrying in %s.\n", err, backoff)
			if err := o.sleep(ctx, backoff); err != nil {
				return nil, err
			}
			backoff = min(backoff*2, pairBackoffMax)
			continue
		}
		return nil, err
	}
}

// transientPairError reports whether a pairing failure may clear without a
// new configuration: a clock skew (once NTP is fixed), a rate limit, the
// platform unavailable, a network error. With an enrollment token, only
// failures from before the platform could spend it count (a 500 or a
// generic 401 may come after).
func transientPairError(err error, token bool) bool {
	var ce *ClockSkewError
	if errors.As(err, &ce) {
		return true
	}
	var he *httpError
	if errors.As(err, &he) {
		switch he.status {
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway, http.StatusGatewayTimeout:
			return true
		case http.StatusInternalServerError, http.StatusUnauthorized:
			return !token
		}
		return false
	}
	var ue *url.Error
	return errors.As(err, &ue) && !errors.Is(err, context.Canceled)
}

func pairOnce(ctx context.Context, pc *pairClient, signer *sensorsig.Signer, o PairOptions) (*Identity, error) {
	nonce, err := pairing.NewNonce()
	if err != nil {
		return nil, err
	}
	commitment := pairing.Commit(nonce)
	req := pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(signer.PublicKey()),
		Commitment: pairing.Encode(commitment), Code: o.Code, Host: o.Host, SensorID: o.RepairSensorID,
		EnrollmentToken: o.EnrollmentToken}
	if o.EnrollmentToken != "" && o.OrganizationEnrollment {
		req.EnrollmentScope = pairing.EnrollmentScopeOrganization
	}
	var start pairing.StartResponse
	if err := pc.do(ctx, o, http.MethodPost, pairing.StartPath, req, http.StatusCreated, &start); err != nil {
		var he *httpError
		if o.EnrollmentToken != "" && errors.As(err, &he) && he.status == http.StatusUnauthorized {
			return nil, ErrEnrollmentRefused
		}
		return nil, fmt.Errorf("pairing: start: %w", err)
	}
	platformPub, platformNonce, err := pairing.VerifyStart(&start, signer.PublicKey(), commitment, o.PlatformKeyPin, sensorsig.Thumbprint)
	if err != nil {
		return nil, err
	}
	if !validID(start.PairingID) {
		return nil, errors.New("pairing: the platform answered an invalid pairing id")
	}
	path := strings.ReplaceAll(pairing.StatusPath, "{pairing_id}", start.PairingID)
	if err := pc.do(ctx, o, http.MethodPut, path+"/nonce", pairing.RevealRequest{SensorNonce: pairing.Encode(nonce)}, http.StatusNoContent, nil); err != nil {
		return nil, fmt.Errorf("pairing: reveal: %w", err)
	}
	sas := pairing.ComputeSAS(signer.PublicKey(), platformPub, nonce, platformNonce)
	printInstructions(o, start, sas, signer.KeyID())

	for {
		var st pairing.StatusResponse
		err := pc.do(ctx, o, http.MethodGet, path, nil, http.StatusOK, &st)
		var he *httpError
		switch {
		case errors.As(err, &he) && he.status == http.StatusNotFound:
			return nil, ErrExpired // purged or expired
		case err != nil:
			return nil, fmt.Errorf("pairing: status: %w", err)
		}
		switch st.Status {
		case pairing.StatusDenied:
			return nil, ErrDenied
		case pairing.StatusExpired:
			return nil, ErrExpired
		case pairing.StatusApproved, pairing.StatusCompleted:
			if st.Identity == nil {
				return nil, errors.New("pairing: approved without an identity")
			}
			return confirm(ctx, pc, signer, o, start.PairingID, path, st.Identity, platformPub)
		}
		wait := time.Duration(max(st.PollSeconds, start.PollSeconds, 2)) * time.Second
		if err := o.sleep(ctx, min(wait, 30*time.Second)); err != nil {
			return nil, err
		}
	}
}

func confirm(ctx context.Context, pc *pairClient, signer *sensorsig.Signer, o PairOptions, pairingID, path string, granted *pairing.Identity, platformPub ed25519.PublicKey) (*Identity, error) {
	if granted.KeyID != signer.KeyID() || !validID(granted.SensorID) {
		return nil, errors.New("pairing: the platform granted an identity for another key")
	}
	// An instance enrollment yields a shared sensor (no tenant) and nothing
	// else; any other pairing yields a sensor of one organization.
	if o.EnrollmentToken != "" && !o.OrganizationEnrollment {
		if granted.Scope != pairing.ScopeInstance || granted.TenantID != "" {
			return nil, errors.New("pairing: the platform answered an instance enrollment with an organization identity")
		}
	} else if granted.Scope != "" || !validID(granted.TenantID) {
		return nil, errors.New("pairing: the platform granted an identity without an organization")
	}
	if o.RepairSensorID != "" && granted.SensorID != o.RepairSensorID {
		return nil, errors.New("pairing: the platform re-paired another sensor than the one asked for")
	}
	sig := signer.SignBytes(pairing.ConfirmTranscript(pairingID, granted.SensorID, granted.TenantID, granted.KeyID))
	var done pairing.StatusResponse
	creq := pairing.ConfirmRequest{SensorID: granted.SensorID, KeyID: granted.KeyID, Signature: pairing.Encode(sig)}
	if err := pc.do(ctx, o, http.MethodPost, path+"/complete", creq, http.StatusOK, &done); err != nil {
		return nil, fmt.Errorf("pairing: confirm: %w", err)
	}
	if done.Status != pairing.StatusCompleted {
		return nil, fmt.Errorf("pairing: confirm answered %q", done.Status)
	}
	id := &Identity{PlatformURL: o.BaseURL, SensorID: granted.SensorID, TenantID: granted.TenantID,
		TenantName: granted.TenantName, Name: granted.Name, KeyID: granted.KeyID, Scope: granted.Scope,
		PlatformKey: pairing.Encode(platformPub), PairedAt: time.Now().UTC(),
		// A sensor paired from now on fails closed without a local policy,
		// and never starts out accepting unsigned jobs.
		RequireLocalPolicy: true, RequireSignedJobs: !o.AllowUnsignedJobs}
	id.PlatformTLSPinElement, id.PlatformTLSPin = pc.tlsPin()
	var err error
	if id.JobSigningKeys, id.JobSigningRoot, err = pc.jobSigning(ctx, o); err != nil {
		return nil, err
	}
	id.ContentPlatformKeys, id.ContentTenantKeys = contentKeys(o, granted)
	if err := o.Store.Save(id); err != nil {
		return nil, err
	}
	if id.Scope == pairing.ScopeInstance {
		_, _ = fmt.Fprintf(o.Out, "Enrolled: shared sensor %q (%s) of the instance. Identity saved in %s.\n", id.Name, id.SensorID, o.Store.Dir())
	} else {
		org := id.TenantName
		if org == "" {
			org = id.TenantID
		}
		_, _ = fmt.Fprintf(o.Out, "Paired: sensor %q (%s) in organization %s. Identity saved in %s.\n", id.Name, id.SensorID, org, o.Store.Dir())
	}
	if id.PlatformTLSPin != "" {
		_, _ = fmt.Fprintf(o.Out, "Platform TLS pinned: %s (%s); a platform certificate from another CA is refused until the sensor is paired again.\n",
			id.PlatformTLSPin, id.PlatformTLSPinElement)
	}
	if len(id.JobSigningKeys) > 0 {
		ids := make([]string, 0, len(id.JobSigningKeys))
		for _, k := range id.JobSigningKeys {
			ids = append(ids, k.KeyID)
		}
		_, _ = fmt.Fprintf(o.Out, "Job signer pinned: %s; this sensor runs only jobs the platform's signer signed.\n", strings.Join(ids, ", "))
	}
	if n := len(id.ContentPlatformKeys) + len(id.ContentTenantKeys); n > 0 {
		_, _ = fmt.Fprintf(o.Out, "Content keys pinned: %d platform, %d organization; content packs are accepted only when signed by them.\n", len(id.ContentPlatformKeys), len(id.ContentTenantKeys))
	}
	if id.JobSigningRoot != "" {
		how := "named by the platform's key set"
		if o.JobSigningRoot != "" {
			how = "SENSOR_JOB_SIGNING_ROOT, out of band; the platform's key set is signed by it"
		}
		_, _ = fmt.Fprintf(o.Out, "Job-signing root pinned: %s (%s); signer keys are accepted from the key sets it signs.\n", id.JobSigningRoot, how)
	}
	if id.RequireSignedJobs && id.JobSigningRoot == "" && len(id.JobSigningKeys) == 0 {
		_, _ = fmt.Fprintf(o.Out, "WARNING: the platform served no job signer: this sensor requires signed jobs and will not start until SENSOR_JOB_SIGNING_ROOT (shown in the console) is set or the platform runs its job signer and the sensor is paired again.\n")
	}
	return id, nil
}

// contentKeys are the content-signing keys the pairing granted, each one's
// id recomputed; a key that is not valid is left out with a warning. A shared
// sensor takes no tenant key.
func contentKeys(o PairOptions, granted *pairing.Identity) (platform, tenant []jobsig.PublicKey) {
	cs := granted.ContentSigning
	if cs == nil {
		return nil, nil
	}
	conv := func(in []pairing.ContentKey, what string) []jobsig.PublicKey {
		var out []jobsig.PublicKey
		for _, k := range in {
			pk := jobsig.PublicKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
			if _, err := pk.Decode(); err != nil {
				_, _ = fmt.Fprintf(o.Out, "WARNING: the platform granted a %s content-signing key that is not valid; not pinned: %v\n", what, err)
				continue
			}
			out = append(out, pk)
		}
		return out
	}
	platform = conv(cs.Platform, "platform")
	if granted.Scope != pairing.ScopeInstance {
		tenant = conv(cs.Tenant, "organization")
	}
	return platform, tenant
}

// ErrJobSigningRootMismatch: the key set the platform serves is not signed
// by the root given out of band (SENSOR_JOB_SIGNING_ROOT).
var ErrJobSigningRootMismatch = errors.New("pairing: the platform's job-signing key set is not signed by SENSOR_JOB_SIGNING_ROOT")

// jobSigning returns the job signer's keys the platform's hello lists now,
// and the root of the key set it serves, over the pairing connection (the
// platform TLS pin and the sensor's new signature). Each key's id is
// recomputed; one that does not match is left out.
//
// With o.JobSigningRoot (out of band) the served key set must be signed by
// that root and current; otherwise pairing fails (ErrJobSigningRootMismatch)
// and nothing is saved: the platform may be lying about its signer. Without
// it the root the key set names is pinned on first use. A hello that cannot
// be read, or a platform that serves no signer, pins nothing (with a
// warning); a new identity still requires signed jobs (RequireSignedJobs).
func (c *pairClient) jobSigning(ctx context.Context, o PairOptions) ([]jobsig.PublicKey, string, error) {
	pinnedRoot, _ := jobsig.ParseRoot(o.JobSigningRoot) // validated by Pair
	var h protov2.Hello
	if err := c.do(ctx, o, http.MethodGet, protov2.HelloPath, nil, http.StatusOK, &h); err != nil {
		if pinnedRoot != "" {
			return nil, "", fmt.Errorf("%w: the platform's hello could not be read: %w", ErrJobSigningRootMismatch, err)
		}
		_, _ = fmt.Fprintf(o.Out, "WARNING: could not read the platform's job-signing keys (%v); nothing is pinned.\n", err)
		return nil, "", nil
	}
	if h.SignedJobs == nil || h.SignedJobs.PayloadType != jobsig.PayloadType {
		if pinnedRoot != "" {
			return nil, "", fmt.Errorf("%w: the platform does not sign jobs", ErrJobSigningRootMismatch)
		}
		return nil, "", nil
	}
	root := ""
	switch {
	case pinnedRoot != "":
		if len(h.SignedJobs.KeySet) == 0 {
			return nil, "", fmt.Errorf("%w: the platform serves no key set", ErrJobSigningRootMismatch)
		}
		if _, err := jobsig.VerifyKeySet(h.SignedJobs.KeySet, pinnedRoot, time.Now()); err != nil {
			return nil, "", fmt.Errorf("%w (%s): %w", ErrJobSigningRootMismatch, pinnedRoot, err)
		}
		root = pinnedRoot
	case len(h.SignedJobs.KeySet) > 0:
		ks, err := jobsig.TrustOnFirstUse(h.SignedJobs.KeySet, time.Now())
		if err != nil {
			_, _ = fmt.Fprintf(o.Out, "WARNING: the platform serves a job-signing key set that is not valid; its root is not pinned: %v\n", err)
		} else {
			root = ks.RootKeyID
		}
	}
	var keys []jobsig.PublicKey
	for _, k := range h.SignedJobs.Keys {
		pk := jobsig.PublicKey{KeyID: k.KeyID, Algorithm: k.Algorithm, PublicKey: k.PublicKey}
		if _, err := pk.Decode(); err != nil {
			_, _ = fmt.Fprintf(o.Out, "WARNING: the platform lists a job-signing key that is not valid; not pinned: %v\n", err)
			continue
		}
		keys = append(keys, pk)
	}
	if len(keys) == 0 && root == "" && h.Supports(protov2.FeatureSignedJobs) {
		_, _ = fmt.Fprintf(o.Out, "WARNING: the platform announces signed jobs but serves no valid signer key or key set; nothing is pinned.\n")
	}
	return keys, root, nil
}

// tlsPin is the platform TLS pin the identity stores: SENSOR_CA_FINGERPRINT
// (httpsec.SetAPIPinnedCA) when set, else the anchor key the pairing
// connections verified; none over plain http.
func (c *pairClient) tlsPin() (element, pin string) {
	if fp := httpsec.APIPinnedCA(); len(fp) > 0 {
		return httpsec.PinElementCACert, httpsec.FormatFingerprint(fp)
	}
	if c.rec != nil {
		if fp := c.rec.Pin(); len(fp) > 0 {
			return httpsec.PinElementAnchorSPKI, httpsec.FormatFingerprint(fp)
		}
	}
	return "", ""
}

func printInstructions(o PairOptions, start pairing.StartResponse, sas pairing.SAS, keyID string) {
	exp := start.ExpiresAt.Local().Format("15:04")
	w := o.Out
	if o.EnrollmentToken != "" && o.OrganizationEnrollment {
		_, _ = fmt.Fprintf(w, "\nEnrolling in the organization with its enrollment token (request expires %s).\n", exp)
		_, _ = fmt.Fprintf(w, "  Fingerprint: %s\n", sas)
		_, _ = fmt.Fprintf(w, "  Key:         %s\n", pairing.KeyFingerprint(keyID))
		_, _ = fmt.Fprintf(w, "If the token requires approval, an administrator compares this fingerprint under Sensors > Enrollment tokens.\n\n")
		return
	}
	if o.EnrollmentToken != "" {
		_, _ = fmt.Fprintf(w, "\nEnrolling as a shared sensor with the instance enrollment token (expires %s).\n", exp)
		_, _ = fmt.Fprintf(w, "  Key:         %s\n\n", pairing.KeyFingerprint(keyID))
		return
	}
	if o.Code == "" {
		_, _ = fmt.Fprintf(w, "\nPair this sensor in OpenCTEM: Sensors > Add sensor > Pair a sensor that shows a code\n")
		_, _ = fmt.Fprintf(w, "  Code:        %s\n", start.UserCode)
		_, _ = fmt.Fprintf(w, "  (Or create a pairing code first under Sensors > Add sensor and start the sensor with SENSOR_PAIRING_CODE set to it.)\n")
	} else {
		shown := pairing.FormatCode(o.Code)
		if o.CodeLabel != "" {
			shown = "from " + o.CodeLabel
		}
		_, _ = fmt.Fprintf(w, "\nAttached to pairing code %s. In the console, check that the fingerprint matches before approving.\n",
			shown)
	}
	_, _ = fmt.Fprintf(w, "  Fingerprint: %s    (expires %s)\n", sas, exp)
	_, _ = fmt.Fprintf(w, "  Key:         %s\n", pairing.KeyFingerprint(keyID))
	_, _ = fmt.Fprintf(w, "Approve it only if the console shows the same fingerprint. Waiting for approval...\n\n")
}

// validID accepts what the platform uses as ids (UUIDs): short, no path or
// query characters, so an id from the answer can be put in a path.
func validID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') && r != '-' {
			return false
		}
	}
	return true
}

type pairClient struct {
	base string
	hc   *http.Client
	ua   string
	rec  *httpsec.PinRecorder
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }

// do sends one request, waiting out a 429 (Retry-After) a few times.
func (c *pairClient) do(ctx context.Context, o PairOptions, method, path string, in any, want int, out any) error {
	var body []byte
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = b
	}
	for attempt := 0; ; attempt++ {
		var rd io.Reader
		if body != nil {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
		if err != nil {
			return err
		}
		if body != nil {
			req.Header.Set("Content-Type", protov2.MediaTypeJSON)
		}
		req.Header.Set("Accept", protov2.MediaTypeJSON+", "+protov2.MediaTypeProblem)
		if c.ua != "" {
			req.Header.Set("User-Agent", useragent.WithProduct(c.ua))
		} else {
			req.Header.Set("User-Agent", useragent.String())
		}
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt < 5 {
			wait, _ := strconv.Atoi(resp.Header.Get("Retry-After"))
			d := time.Duration(min(max(wait, 1), 300)) * time.Second
			_, _ = fmt.Fprintf(o.Out, "Rate limited by the platform (HTTP 429); retrying in %s.\n", d)
			if err := o.sleep(ctx, d); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode == http.StatusUnauthorized {
			if ce := clockSkewOf(resp, data, time.Now()); ce != nil {
				return ce
			}
		}
		if resp.StatusCode != want {
			return &httpError{status: resp.StatusCode, body: strings.TrimSpace(string(data[:min(len(data), 300)]))}
		}
		if out != nil {
			if err := json.Unmarshal(data, out); err != nil {
				return fmt.Errorf("decode answer: %w", err)
			}
		}
		return nil
	}
}

// clockSkewOf reads a 401 as a clock skew: the platform's clock-skew
// problem, or (a platform that answers only the generic 401) a Date header
// further from this machine's clock than the signature tolerance.
func clockSkewOf(resp *http.Response, body []byte, now time.Time) *ClockSkewError {
	if p := protov2.ParseProblem(body); p.Name() == protov2.ProblemClockSkew && p.ClockOffsetSeconds != nil {
		return &ClockSkewError{Offset: time.Duration(*p.ClockOffsetSeconds) * time.Second}
	}
	date, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return nil
	}
	if d := now.Sub(date); d > sensorsig.MaxClockSkew || d < -sensorsig.MaxClockSkew {
		return &ClockSkewError{Offset: d.Truncate(time.Second)}
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
