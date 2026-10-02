package sensorkit

import (
	"fmt"
	"io"
	"os"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/httpsec"
)

// Proxy settings (api RFC-034 §6.1, Phase 0). A sensor has three outbound
// paths, each configured on its own:
//
//	path      setting                  precedence (first set wins)
//	control   SENSOR_CONTROL_PROXY     option, SENSOR_CONTROL_PROXY, HTTP(S)_PROXY / NO_PROXY
//	content   SENSOR_CONTENT_PROXY     option, SENSOR_CONTENT_PROXY, the control setting
//	scanners  SENSOR_SCAN_PROXY        option, SENSOR_SCAN_PROXY, OPENCTEM_SDK_SCANNER_PROXY, inherit
//
// control is every request to the platform (the API client, the heartbeat,
// key renewal). content is scanner content and public feeds fetched by the
// SDK or by a content tool (core.ContentEnviron). scanners is what scanner
// processes get (core.ScannerProxyMode).
//
// A control or content value is a proxy URL (http, https, socks5, socks5h;
// user:password allowed), or "direct" for no proxy. With a URL, NO_PROXY
// (or no_proxy) of the environment is the bypass list. A scanners value is
// inherit (the sensor's environment proxy variables, today's behavior) or
// direct (none).
//
// SENSOR_CA_CERT_FILE is trusted on the control and content paths, so a
// TLS-inspecting egress proxy works for both. Scanners get SSL_CERT_FILE and
// friends from the environment, as before.
const (
	EnvControlProxy = "SENSOR_CONTROL_PROXY"
	EnvContentProxy = "SENSOR_CONTENT_PROXY"
	EnvScanProxy    = "SENSOR_SCAN_PROXY"
)

// Proxies is the resolved proxy configuration of the three paths.
type Proxies struct {
	Control httpsec.ProxySetting
	Content httpsec.ProxySetting
	Scan    core.ScannerProxyMode
}

// ProxyOptions are explicit values (a flag, a configuration file) that win
// over the environment. Empty means "not set".
type ProxyOptions struct {
	Control string
	Content string
	Scan    string
}

// ResolveProxies resolves the three paths' settings (see the table above).
// A value it cannot use is an error naming the setting (exit code
// ExitUsage). It changes nothing: Apply does.
func ResolveProxies(opts ProxyOptions) (Proxies, error) {
	noProxy := firstNonEmpty(os.Getenv("NO_PROXY"), os.Getenv("no_proxy"))
	var p Proxies
	var err error

	controlSrc, control := sourced(opts.Control, EnvControlProxy)
	if p.Control, err = httpsec.ParseProxySetting(control, noProxy); err != nil {
		return Proxies{}, usageError(fmt.Errorf("%s: %w", controlSrc, err))
	}

	contentSrc, content := sourced(opts.Content, EnvContentProxy)
	if content == "" {
		p.Content = p.Control
	} else if p.Content, err = httpsec.ParseProxySetting(content, noProxy); err != nil {
		return Proxies{}, usageError(fmt.Errorf("%s: %w", contentSrc, err))
	}

	scanSrc, scan := sourced(opts.Scan, EnvScanProxy)
	if scan == "" {
		p.Scan = core.ScannerProxy()
	} else if p.Scan, err = core.ParseScannerProxyMode(scan); err != nil {
		return Proxies{}, usageError(fmt.Errorf("%s: %w", scanSrc, err))
	}
	return p, nil
}

func sourced(explicit, env string) (source, value string) {
	if explicit != "" {
		return "proxy option", explicit
	}
	return env, os.Getenv(env)
}

// Apply installs the settings: API clients and SafeHTTPClients created
// afterwards use them, and so do scanner and content processes started
// afterwards. Call it before the platform client is created.
func (p Proxies) Apply() {
	httpsec.SetAPIProxy(p.Control)
	httpsec.SetContentProxy(p.Content)
	core.SetScannerProxyMode(p.Scan)
}

// Summary is one line for the start-up log, without credentials.
func (p Proxies) Summary() string {
	scan := string(core.ScannerProxyDirect)
	if p.Scan != core.ScannerProxyDirect {
		scan = string(core.ScannerProxyInherit) + " (no proxy variables set)"
		if env := httpsec.EnvironmentProxySummary(); env != "" {
			scan = string(core.ScannerProxyInherit) + " (" + env + ")"
		}
	}
	return fmt.Sprintf("Proxy: platform=%s, content=%s, scanners=%s", p.Control, p.Content, scan)
}

// ScanWarning is the warning for scanners that inherit the sensor's proxy
// variables (RFC-034 G1), or "" when there is nothing to warn about.
func (p Proxies) ScanWarning() string {
	if p.Scan != core.ScannerProxyInherit {
		return ""
	}
	env := httpsec.EnvironmentProxySummary()
	if env == "" {
		return ""
	}
	return fmt.Sprintf("Warning: scanner processes inherit this sensor's proxy variables (%s). "+
		"Their traffic to targets goes through that proxy unless NO_PROXY lists the target; "+
		"internal targets usually should not. Set %s=direct to stop it, or %s=inherit to keep it and silence this warning.",
		env, EnvScanProxy, EnvScanProxy)
}

// report prints the summary when any proxy is in play, and the warning
// unless the operator chose inherit explicitly.
func (p Proxies) report(out, errw io.Writer, opts ProxyOptions) {
	if p.Control.Mode != httpsec.ProxyEnvironment || p.Content.Mode != httpsec.ProxyEnvironment ||
		p.Scan == core.ScannerProxyDirect || httpsec.EnvironmentProxySummary() != "" {
		_, _ = fmt.Fprintln(out, p.Summary())
	}
	_, explicit := sourced(opts.Scan, EnvScanProxy)
	if explicit == "" {
		explicit = os.Getenv(core.EnvScannerProxy)
	}
	if w := p.ScanWarning(); w != "" && explicit == "" {
		_, _ = fmt.Fprintln(errw, w)
	}
}
