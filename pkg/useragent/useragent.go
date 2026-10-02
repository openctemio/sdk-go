// Package useragent builds the User-Agent the SDK sends to the platform and
// to the services its collectors and enrichers call:
//
//	[<product>/<version> ]openctem-sdk-go/<sdk version>
//
// for example "openctemio-sensor/0.3.1 openctem-sdk-go/0.7.4". Operators use
// it to tell old agents from new sensors, and one SDK release from another,
// in proxy and API logs.
//
// The SDK version is read from the binary's build info. The embedding binary
// names itself once, at startup, with SetProduct; every SDK HTTP client in the
// process then sends it. pkg/client also takes a per-client product
// (client.Config.UserAgent, client.WithUserAgent).
package useragent

import (
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/openctemio/sdk-go/pkg/sdk"
)

const (
	// sdkModule is the module path whose version is reported.
	sdkModule = "github.com/openctemio/sdk-go"
	// sdkToken is the SDK's product name in the User-Agent.
	sdkToken = sdk.Name
	// develSuffix marks a build from a local checkout (go test, go run, a
	// replace directive): "<sdk.Version>-devel".
	develSuffix = "-devel"
	// maxProductLen bounds the embedding binary's product token.
	maxProductLen = 128
)

var (
	sdkVersionOnce sync.Once
	sdkVersion     string

	product atomic.Value // string
)

// SDKVersion returns the version of github.com/openctemio/sdk-go linked into
// this binary, without a leading "v": the module version from the build info
// (set by the release tag the sensor was built against), "<sdk.Version>-devel"
// for a build from a local checkout, or sdk.Version when the binary has no
// build info.
func SDKVersion() string {
	sdkVersionOnce.Do(func() {
		sdkVersion = versionFromBuildInfo(debug.ReadBuildInfo())
	})
	return sdkVersion
}

// versionFromBuildInfo picks the SDK's version from build info: the
// dependency entry when the SDK is a dependency (the replacement's version
// when it is replaced), the main module's when the SDK itself is being built.
func versionFromBuildInfo(info *debug.BuildInfo, ok bool) string {
	if !ok || info == nil {
		return sdk.Version
	}
	version := ""
	if info.Main.Path == sdkModule {
		version = info.Main.Version
	}
	linked := info.Main.Path == sdkModule
	for _, dep := range info.Deps {
		if dep.Path != sdkModule {
			continue
		}
		linked = true
		version = dep.Version
		if dep.Replace != nil {
			version = dep.Replace.Version
		}
		break
	}
	if !linked {
		return sdk.Version
	}
	return cleanVersion(version)
}

// cleanVersion drops the leading "v" and maps empty and "(devel)" to
// "<sdk.Version>-devel".
func cleanVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if v == "" || v == "(devel)" {
		return sdk.Version + develSuffix
	}
	return sanitize(v)
}

// SetProduct names the binary embedding the SDK, for every SDK HTTP client in
// the process: SetProduct("openctemio-sensor", "0.3.1"). A leading "v" on the
// version is dropped; an empty version sends the name alone. Characters not
// allowed in an HTTP token are removed and the result is bounded, so a value
// from configuration cannot inject headers. Call it once at startup, before
// the first request.
func SetProduct(name, version string) {
	product.Store(Product(name, version))
}

// Product formats and sanitizes a "name/version" product token. It returns ""
// when name is empty after sanitizing.
func Product(name, version string) string {
	name = sanitize(name)
	if name == "" {
		return ""
	}
	version = sanitize(strings.TrimPrefix(strings.TrimSpace(version), "v"))
	p := name
	if version != "" {
		p += "/" + version
	}
	if len(p) > maxProductLen {
		p = p[:maxProductLen]
	}
	return p
}

// ProductName returns the name and version of the product set with
// SetProduct ("" when none was set).
func ProductName() (name, version string) {
	p, _ := product.Load().(string)
	name, version, _ = strings.Cut(p, "/")
	return name, version
}

// String returns the User-Agent for the product set with SetProduct.
func String() string {
	p, _ := product.Load().(string)
	return WithProduct(p)
}

// WithProduct returns the User-Agent for an explicit product token (already
// formatted as "name/version", possibly several separated by spaces). The
// token is sanitized and bounded; an empty one yields the SDK token alone.
func WithProduct(p string) string {
	p = sanitizeProducts(p)
	sdk := sdkToken + "/" + SDKVersion()
	if p == "" {
		return sdk
	}
	return p + " " + sdk
}

// sanitizeProducts keeps a space-separated list of product tokens, each
// sanitized, within maxProductLen.
func sanitizeProducts(p string) string {
	fields := strings.Fields(p)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if s := sanitizeToken(f); s != "" {
			out = append(out, s)
		}
	}
	joined := strings.Join(out, " ")
	if len(joined) > maxProductLen {
		joined = strings.TrimSpace(joined[:maxProductLen])
	}
	return joined
}

// sanitizeToken keeps RFC 9110 token characters plus one "/" separator.
func sanitizeToken(s string) string {
	name, version, hasVersion := strings.Cut(s, "/")
	name = sanitize(name)
	if name == "" {
		return ""
	}
	if !hasVersion {
		return name
	}
	if version = sanitize(version); version == "" {
		return name
	}
	return name + "/" + version
}

// sanitize keeps only RFC 9110 tchar characters (no spaces, slashes, CR/LF
// or other controls).
func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if isTChar(r) {
			b.WriteRune(r)
		}
		if b.Len() >= maxProductLen {
			break
		}
	}
	return b.String()
}

func isTChar(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("!#$%&'*+-.^_`|~", r)
}

// Transport returns a RoundTripper that sets the User-Agent (String, read
// at request time) on every request that does not carry one, then calls
// base (http.DefaultTransport when nil). The request is cloned, never
// modified.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{base: base}
}

type transport struct {
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("User-Agent") != "" {
		return t.base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	r.Header.Set("User-Agent", String())
	return t.base.RoundTrip(r)
}
