package sensorkit

// CT lookups (capability lookup.ct@1): the platform makes no request to a
// Certificate Transparency source itself; it asks a platform-owned shared
// sensor with internet access, one root domain per signed lookup job, on
// behalf of one organization. A shared sensor with a pinned job-signing key
// serves them by default; the host operator turns it off with
// SENSOR_CT_LOOKUP=0. The sources are crt.sh, then Cert Spotter; a host
// operator may point either at a mirror (an https URL of the host's own
// setting, never the platform's) and give a Cert Spotter key.

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/openctemio/contract/ctlookup"
	"github.com/openctemio/sdk-go/pkg/ctlog"
	"github.com/openctemio/sdk-go/pkg/httpsec"
	"github.com/openctemio/sdk-go/pkg/lookupjob"
)

// Environment of the CT lookups.
const (
	// EnvCTLookup: unset or "auto" serves CT lookups on a shared sensor
	// with a pinned job-signing key (off on any other sensor); "0" turns
	// them off; "1" requires them (a usage error on a sensor that cannot).
	EnvCTLookup = "SENSOR_CT_LOOKUP"
	// EnvCTCRTSHURL and EnvCTCertSpotterURL replace the public sources
	// (https base URLs, a mirror for example). EnvCTCertSpotterURL "off"
	// turns the Cert Spotter fallback off.
	EnvCTCRTSHURL       = "SENSOR_CT_CRTSH_URL"
	EnvCTCertSpotterURL = "SENSOR_CT_CERTSPOTTER_URL"
	// EnvCTCertSpotterKey is the operator's Cert Spotter key (optional; the
	// free unauthenticated quota without it). EnvCTCertSpotterKeyFile
	// names a file holding it instead.
	EnvCTCertSpotterKey     = "SENSOR_CT_CERTSPOTTER_KEY"
	EnvCTCertSpotterKeyFile = "SENSOR_CT_CERTSPOTTER_KEY_FILE"
)

// ServeCTLookup makes the kit answer CT lookup jobs and report
// ctlookup.Capability when it can: a shared sensor connected to a platform
// whose job-signing key or root is pinned (the same rule as the feed
// relay). It reports whether CT lookups are on. Call before Run.
func (k *Kit) ServeCTLookup() (bool, error) {
	required := false
	switch v := strings.TrimSpace(os.Getenv(EnvCTLookup)); v {
	case "0":
		return false, nil
	case "", "auto":
	case "1":
		required = true
	default:
		return false, usageError(fmt.Errorf("%s=%q is not recognized: leave it unset (a shared sensor answers the platform's CT lookups), 0 to turn them off, or 1 to require them", EnvCTLookup, v))
	}
	if why := k.ctLookupBlocker(); why != "" {
		if required {
			return false, usageError(fmt.Errorf("%s=1: %s", EnvCTLookup, why))
		}
		return false, nil
	}
	cfg, err := ctLookupConfigFromEnv()
	if err != nil {
		return false, usageError(err)
	}
	c, err := ctlog.New(cfg)
	if err != nil {
		return false, usageError(err)
	}
	k.ctLookup = c
	k.Tools().AddCapabilities(ctlookup.Capability)
	return true, nil
}

// ctLookupBlocker says why this sensor cannot serve CT lookups ("" when it
// can).
func (k *Kit) ctLookupBlocker() string {
	switch why := k.feedRelayBlocker(); {
	case why == "":
		return ""
	case !k.s.shared:
		return "only a shared (platform) sensor answers CT lookups; an organization's sensor never does"
	default:
		return strings.Replace(why, "the feed relay", "CT lookups", 1)
	}
}

// ctLookupConfigFromEnv reads the host's CT source settings.
func ctLookupConfigFromEnv() (ctlog.Config, error) {
	cfg := ctlog.Config{HTTP: httpsec.SafeHTTPClientWith(ctlog.DefaultTimeout, ctlog.DefaultHeaderTimeout), UserAgent: "openctem-sensor-ctlog"}
	if v := strings.TrimSpace(os.Getenv(EnvCTCRTSHURL)); v != "" {
		if err := httpsURL(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", EnvCTCRTSHURL, err)
		}
		cfg.CRTSHURL = v
	}
	switch v := strings.TrimSpace(os.Getenv(EnvCTCertSpotterURL)); v {
	case "":
	case "off":
		cfg.CertSpotterOff = true
	default:
		if err := httpsURL(v); err != nil {
			return cfg, fmt.Errorf("%s: %w", EnvCTCertSpotterURL, err)
		}
		cfg.CertSpotterURL = v
	}
	key := strings.TrimSpace(os.Getenv(EnvCTCertSpotterKey))
	if f := strings.TrimSpace(os.Getenv(EnvCTCertSpotterKeyFile)); f != "" {
		b, err := os.ReadFile(f) // #nosec G304 -- the host operator's own file setting
		if err != nil {
			return cfg, fmt.Errorf("%s: %w", EnvCTCertSpotterKeyFile, err)
		}
		key = strings.TrimSpace(string(b))
	}
	if strings.ContainsAny(key, " \t\r\n") || len(key) > 256 {
		return cfg, fmt.Errorf("%s: not a Cert Spotter key", EnvCTCertSpotterKey)
	}
	if key != "" {
		cfg.CertSpotterKey = func() string { return key }
	}
	return cfg, nil
}

func httpsURL(v string) error {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q is not an https base URL without credentials, query or fragment", v)
	}
	return nil
}

// startCTLookup serves CT lookup jobs until ctx ends (no-op when off).
func (k *Kit) startCTLookup(ctx context.Context) {
	if k.ctLookup == nil {
		return
	}
	r, err := lookupjob.New(lookupjob.Config{
		Platform: k.client, Verifier: k.s.jobs,
		Services: map[string]lookupjob.Service{ctlookup.Capability: {Tool: ctlookup.Tool, Run: k.ctLookup.Job}},
		Logf:     func(format string, args ...any) { _, _ = fmt.Fprintf(k.errw, format+"\n", args...) },
	})
	if err != nil {
		_, _ = fmt.Fprintf(k.errw, "CT lookups off: %v\n", err)
		return
	}
	_, _ = fmt.Fprintf(k.out, "  CT lookups: on (%s)\n", ctlookup.Capability)
	go r.Run(ctx)
}
