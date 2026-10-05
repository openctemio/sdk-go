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
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/httpsec"
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
)

// PairOptions configures Pair.
type PairOptions struct {
	// BaseURL is the platform API URL (API_URL).
	BaseURL string
	// Store keeps the key and receives the identity.
	Store *Store
	// Code attaches to a code an administrator created with "expect a
	// sensor" (reverse mode). Empty: the platform gives a code for the
	// administrator to enter.
	Code string
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
	// Retry starts a new request when one expires (the daemon waits for an
	// administrator indefinitely); off, Pair returns ErrExpired.
	Retry bool
	// Out receives the lines a person reads (the code, the fingerprint).
	Out io.Writer
	// HTTPClient sends the requests; it is wrapped to sign them. Default:
	// httpsec.NewAPIClient (SSRF guard, CA pin, no redirects).
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
	if base == nil {
		base = httpsec.NewAPIClient(30 * time.Second)
	}
	hc := *base
	hc.Transport = &sensorsig.Transport{Signer: signer, Base: base.Transport, MaxBody: 64 << 10}
	pc := &pairClient{base: strings.TrimRight(o.BaseURL, "/") + protov2.PathPrefix, hc: &hc, ua: o.UserAgent}

	for {
		id, err := pairOnce(ctx, pc, signer, o)
		if errors.Is(err, ErrExpired) && o.Retry {
			_, _ = fmt.Fprintln(o.Out, "The pairing request expired; starting a new one.")
			continue
		}
		if err != nil {
			return nil, err
		}
		return id, nil
	}
}

func pairOnce(ctx context.Context, pc *pairClient, signer *sensorsig.Signer, o PairOptions) (*Identity, error) {
	nonce, err := pairing.NewNonce()
	if err != nil {
		return nil, err
	}
	commitment := pairing.Commit(nonce)
	req := pairing.StartRequest{Protocol: pairing.Version, PublicKey: pairing.Encode(signer.PublicKey()),
		Commitment: pairing.Encode(commitment), Code: o.Code, Host: o.Host, SensorID: o.RepairSensorID}
	var start pairing.StartResponse
	if err := pc.do(ctx, o, http.MethodPost, pairing.StartPath, req, http.StatusCreated, &start); err != nil {
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
	if granted.KeyID != signer.KeyID() || !validID(granted.SensorID) || !validID(granted.TenantID) {
		return nil, errors.New("pairing: the platform granted an identity for another key")
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
		TenantName: granted.TenantName, Name: granted.Name, KeyID: granted.KeyID,
		PlatformKey: pairing.Encode(platformPub), PairedAt: time.Now().UTC()}
	if err := o.Store.Save(id); err != nil {
		return nil, err
	}
	org := id.TenantName
	if org == "" {
		org = id.TenantID
	}
	_, _ = fmt.Fprintf(o.Out, "Paired: sensor %q (%s) in organization %s. Identity saved in %s.\n", id.Name, id.SensorID, org, o.Store.Dir())
	return id, nil
}

func printInstructions(o PairOptions, start pairing.StartResponse, sas pairing.SAS, keyID string) {
	exp := start.ExpiresAt.Local().Format("15:04")
	w := o.Out
	if o.Code == "" {
		_, _ = fmt.Fprintf(w, "\nPair this sensor in OpenCTEM: Sensors > Pair a sensor\n")
		_, _ = fmt.Fprintf(w, "  Code:        %s\n", start.UserCode)
	} else {
		_, _ = fmt.Fprintf(w, "\nAttached to pairing code %s. In the console, check that the fingerprint matches before approving.\n",
			pairing.FormatCode(o.Code))
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
			if err := o.sleep(ctx, time.Duration(min(max(wait, 1), 120))*time.Second); err != nil {
				return err
			}
			continue
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
