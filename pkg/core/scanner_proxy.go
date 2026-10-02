package core

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Scanner proxy (api RFC-034 G1, owner decision O2).
//
// A sensor's own proxy (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY) is set
// for its link to the platform. Scanner processes used to inherit it as a
// side effect of the environment allowlist, so a scanner's traffic to an
// internal target could go to the corporate egress proxy unless NO_PROXY
// listed the target. ScannerProxyMode makes this a choice:
//
//   - ScannerProxyInherit (default, today's behavior): scanners get the
//     proxy variables of the sensor's environment. sensorkit logs a warning
//     at start when they are set, naming them.
//   - ScannerProxyDirect: scanners get no proxy variables from the sensor's
//     environment. Variables a caller passes explicitly (ExecConfig.Env,
//     ScanOptions.Env) are still passed.
//
// Content downloads that run a tool (trivy's database, template updates)
// are not scans: they use ContentEnviron, which follows the content proxy
// (httpsec.ContentProxy).

// ScannerProxyMode says whether scanner processes inherit the sensor's proxy
// variables.
type ScannerProxyMode string

const (
	// ScannerProxyInherit passes the sensor's proxy variables to scanners.
	ScannerProxyInherit ScannerProxyMode = "inherit"
	// ScannerProxyDirect removes them.
	ScannerProxyDirect ScannerProxyMode = "direct"
)

// EnvScannerProxy is the SDK setting for the scanner proxy mode: inherit
// (default) or direct. The OpenCTEM sensor reads SENSOR_SCAN_PROXY instead
// (sensorkit), which wins over this one.
const EnvScannerProxy = "OPENCTEM_SDK_SCANNER_PROXY"

// ParseScannerProxyMode parses inherit or direct; "" is inherit.
func ParseScannerProxyMode(v string) (ScannerProxyMode, error) {
	switch m := ScannerProxyMode(strings.ToLower(strings.TrimSpace(v))); m {
	case "":
		return ScannerProxyInherit, nil
	case ScannerProxyInherit, ScannerProxyDirect:
		return m, nil
	default:
		return "", fmt.Errorf("scanner proxy mode %q is not recognized: use inherit (scanners get the sensor's HTTP(S)_PROXY / NO_PROXY) or direct (they do not)", v)
	}
}

var scannerProxy, scannerProxyErr = initScannerProxy()

// initScannerProxy reads EnvScannerProxy. An unrecognized value keeps inherit
// (today's behavior) and is reported by CheckEnv.
func initScannerProxy() (ScannerProxyMode, error) {
	m, err := ParseScannerProxyMode(os.Getenv(EnvScannerProxy))
	if err != nil {
		return ScannerProxyInherit, fmt.Errorf("%s: %w", EnvScannerProxy, err)
	}
	return m, nil
}

// SetScannerProxyMode sets the scanner proxy mode of every scanner process
// started afterwards. An unknown mode is treated as inherit.
func SetScannerProxyMode(m ScannerProxyMode) {
	if m != ScannerProxyDirect {
		m = ScannerProxyInherit
	}
	scannerEnvMu.Lock()
	scannerProxy = m
	scannerEnvMu.Unlock()
}

// ScannerProxy returns the scanner proxy mode.
func ScannerProxy() ScannerProxyMode {
	scannerEnvMu.RLock()
	defer scannerEnvMu.RUnlock()
	return scannerProxy
}

// ScannerProxySummary describes what scanner processes get, for the start-up
// log, without credentials: "inherit (HTTPS_PROXY=http://proxy:3128)",
// "inherit (no proxy variables set)" or "direct".
func ScannerProxySummary() string {
	if ScannerProxy() == ScannerProxyDirect {
		return string(ScannerProxyDirect)
	}
	if s := httpsec.EnvironmentProxySummary(); s != "" {
		return string(ScannerProxyInherit) + " (" + s + ")"
	}
	return string(ScannerProxyInherit) + " (no proxy variables set)"
}

// ContentEnviron is ScannerEnviron for a process that downloads scanner
// content (trivy's database, template or rule updates): its proxy variables
// follow the content proxy (httpsec.ContentProxy) instead of the scanner
// proxy mode.
//   - environment: the sensor's proxy variables, as they are;
//   - direct: none;
//   - a URL: HTTP_PROXY, HTTPS_PROXY and ALL_PROXY (both spellings) set to
//     it, and NO_PROXY to the setting's bypass list.
func ContentEnviron(extra ...map[string]string) []string {
	return contentEnviron(os.Environ(), httpsec.ContentProxy(), extra...)
}

func contentEnviron(base []string, s httpsec.ProxySetting, extra ...map[string]string) []string {
	switch s.Mode {
	case httpsec.ProxyDirect:
		return buildEnviron(base, true, nil, extra...)
	case httpsec.ProxyURL:
		if s.URL == nil {
			return buildEnviron(base, true, nil, extra...)
		}
		u := s.URL.String()
		vars := map[string]string{
			"HTTP_PROXY": u, "HTTPS_PROXY": u, "ALL_PROXY": u,
			"http_proxy": u, "https_proxy": u, "all_proxy": u,
		}
		if s.NoProxy != "" {
			vars["NO_PROXY"], vars["no_proxy"] = s.NoProxy, s.NoProxy
		}
		return buildEnviron(base, true, vars, extra...)
	default:
		return buildEnviron(base, false, nil, extra...)
	}
}

func isProxyEnvVar(name string) bool {
	for _, n := range httpsec.ProxyEnvVars {
		if name == n {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
