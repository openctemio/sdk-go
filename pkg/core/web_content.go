package core

import (
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Web content a probe or a crawler learned about a response. A scanned server
// chooses every byte of it, so each value passes a bound here before a sensor
// reports it, and a value that is not on the allow-list never leaves the
// sensor: parameter values, query values and cookie values are not carried by
// any type in this file.

const (
	// MaxWebURLBytes is the longest URL a sensor reports.
	MaxWebURLBytes = 2048
	// MaxURLParams is the most parameters one discovered URL carries.
	MaxURLParams = 100
	// MaxURLForms is the most forms one discovered URL carries.
	MaxURLForms = 20
	// MaxParamNameBytes is the longest parameter name.
	MaxParamNameBytes = 128
	// MaxContentTypeBytes is the longest media type.
	MaxContentTypeBytes = 255
	// MaxHeaderValueBytes is the longest allow-listed header value; a longer
	// value is dropped, not cut, so a truncated policy is never reported.
	MaxHeaderValueBytes = 4096
	// MaxCookies is the most cookies reported for one response.
	MaxCookies = 20
	// MaxCNAMEs is the longest alias chain reported.
	MaxCNAMEs = 8
	// maxLabelBytes bounds the free-text labels (type, source, extension).
	maxLabelBytes = 64
)

// Parameter locations a sensor reports.
const (
	ParamLocationQuery  = "query"
	ParamLocationForm   = "form"
	ParamLocationHeader = "header"
	ParamLocationCookie = "cookie"
	ParamLocationPath   = "path"
	ParamLocationJSON   = "json"
)

var paramLocations = map[string]bool{
	ParamLocationQuery: true, ParamLocationForm: true, ParamLocationHeader: true,
	ParamLocationCookie: true, ParamLocationPath: true, ParamLocationJSON: true,
	"multipart": true, "graphql_arg": true,
}

// URLParam is one parameter of a URL: where it goes and its name.
type URLParam struct {
	Location string `json:"location"`
	Name     string `json:"name"`
}

// WebForm is one HTML form. It carries field names and one flag, never a
// default or entered value.
type WebForm struct {
	// Method is GET or POST.
	Method string `json:"method,omitempty"`
	// Action is the form target without query, user info or fragment; empty
	// when the form posts to the page itself or the action was not http(s).
	Action string `json:"action,omitempty"`
	// Params are the field names (location form).
	Params []URLParam `json:"params,omitempty"`
	// PasswordField is true when the form has a password input.
	PasswordField bool `json:"password_field,omitempty"`
}

// CookieFlags is what a Set-Cookie header says about a cookie, without its
// value, domain or path.
type CookieFlags struct {
	Name       string `json:"name"`
	Secure     bool   `json:"secure,omitempty"`
	HTTPOnly   bool   `json:"http_only,omitempty"`
	SameSite   string `json:"same_site,omitempty"` // strict, lax or none
	Persistent bool   `json:"persistent,omitempty"`
}

// ResponseHeaders is the posture subset of a response's headers.
type ResponseHeaders struct {
	// Values maps a canonical allow-listed header name to its value.
	Values map[string]string `json:"values,omitempty"`
	// Cookies are the names and flags of the cookies the response sets.
	Cookies []CookieFlags `json:"cookies,omitempty"`
}

// postureHeaders is the allow-list of response headers whose value is a
// security policy and so safe to report. Anything else (Server, Date,
// Authorization echoes, custom headers, cookies) is dropped by name.
var postureHeaders = map[string]string{
	"strict-transport-security":        "Strict-Transport-Security",
	"content-security-policy":          "Content-Security-Policy",
	"x-frame-options":                  "X-Frame-Options",
	"x-content-type-options":           "X-Content-Type-Options",
	"referrer-policy":                  "Referrer-Policy",
	"permissions-policy":               "Permissions-Policy",
	"access-control-allow-origin":      "Access-Control-Allow-Origin",
	"access-control-allow-credentials": "Access-Control-Allow-Credentials",
}

// AllowedResponseHeaders returns the canonical names of the headers whose
// value ResponseHeadersFrom reports.
func AllowedResponseHeaders() []string {
	return []string{
		"Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
		"X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
		"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials",
	}
}

// ResponseHeadersFrom reduces a response's headers to the allow-list. Header
// names match case-insensitively. Set-Cookie lines contribute names and flags
// only. A value with a control character, invalid UTF-8 or more than
// MaxHeaderValueBytes is dropped. It returns nil when nothing is left.
func ResponseHeadersFrom(h map[string][]string) *ResponseHeaders {
	out := &ResponseHeaders{}
	for name, vals := range h {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "set-cookie" {
			for _, line := range vals {
				if c, ok := CookieFlagsFrom(line); ok && len(out.Cookies) < MaxCookies {
					out.Cookies = append(out.Cookies, c)
				}
			}
			continue
		}
		canon, ok := postureHeaders[key]
		if !ok {
			continue
		}
		if v, ok := headerValue(vals); ok {
			if out.Values == nil {
				out.Values = map[string]string{}
			}
			out.Values[canon] = v
		}
	}
	sortCookies(out.Cookies)
	if len(out.Values) == 0 && len(out.Cookies) == 0 {
		return nil
	}
	return out
}

// Bound applies the allow-list and the bounds again to a value that came
// through JSON, so a decoded ResponseHeaders is as safe as a built one.
func (r *ResponseHeaders) Bound() *ResponseHeaders {
	if r == nil {
		return nil
	}
	in := map[string][]string{}
	for k, v := range r.Values {
		in[k] = []string{v}
	}
	out := ResponseHeadersFrom(in)
	for _, c := range r.Cookies {
		if len(cookiesOf(out)) >= MaxCookies {
			break
		}
		if !validCookieName(c.Name) {
			continue
		}
		if out == nil {
			out = &ResponseHeaders{}
		}
		c.SameSite = sameSite(c.SameSite)
		out.Cookies = append(out.Cookies, c)
	}
	if out != nil {
		sortCookies(out.Cookies)
	}
	return out
}

func cookiesOf(r *ResponseHeaders) []CookieFlags {
	if r == nil {
		return nil
	}
	return r.Cookies
}

func sortCookies(c []CookieFlags) {
	for i := 1; i < len(c); i++ {
		for j := i; j > 0 && c[j].Name < c[j-1].Name; j-- {
			c[j], c[j-1] = c[j-1], c[j]
		}
	}
}

func headerValue(vals []string) (string, bool) {
	var parts []string
	for _, v := range vals {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if !cleanText(v) {
			return "", false
		}
		parts = append(parts, v)
	}
	v := strings.Join(parts, ", ")
	if v == "" || len(v) > MaxHeaderValueBytes {
		return "", false
	}
	return v, true
}

// cleanText reports whether s is valid UTF-8 without control characters
// (which includes CR, LF and NUL).
func cleanText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' || r == '\u202e' {
			return false
		}
	}
	return true
}

// CookieFlagsFrom parses one Set-Cookie line into its name and flags. The
// value, Domain, Path, Expires and Max-Age values are read for the flags and
// discarded. It reports false for a line without a valid cookie name.
func CookieFlagsFrom(line string) (CookieFlags, bool) {
	if len(line) > 8*MaxHeaderValueBytes || !cleanText(line) {
		return CookieFlags{}, false
	}
	parts := strings.Split(line, ";")
	name, _, found := strings.Cut(parts[0], "=")
	name = strings.TrimSpace(name)
	if !found || !validCookieName(name) {
		return CookieFlags{}, false
	}
	c := CookieFlags{Name: name}
	for _, a := range parts[1:] {
		k, v, _ := strings.Cut(a, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "secure":
			c.Secure = true
		case "httponly":
			c.HTTPOnly = true
		case "samesite":
			c.SameSite = sameSite(v)
		case "expires", "max-age":
			c.Persistent = true
		}
	}
	return c, true
}

func sameSite(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "strict":
		return "strict"
	case "lax":
		return "lax"
	case "none":
		return "none"
	}
	return ""
}

// validCookieName accepts an RFC 6265 token of at most 128 bytes.
func validCookieName(n string) bool {
	if n == "" || len(n) > MaxParamNameBytes {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if c <= 0x20 || c >= 0x7f || strings.IndexByte("()<>@,;:\\\"/[]?={}", c) >= 0 {
			return false
		}
	}
	return true
}

// SanitizeCNAMEs keeps the valid host names of an alias chain, lower-cased,
// at most MaxCNAMEs of them.
func SanitizeCNAMEs(in []string) []string {
	var out []string
	for _, c := range in {
		c = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c), "."))
		if !validHostName(c) {
			continue
		}
		out = append(out, c)
		if len(out) == MaxCNAMEs {
			break
		}
	}
	return out
}

func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		ok := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_'
		if !ok {
			return false
		}
	}
	return !strings.Contains(h, "..") && h[0] != '.'
}

// SanitizeURLParams keeps the parameters with a known location and a valid
// name, without duplicates, at most MaxURLParams of them.
func SanitizeURLParams(in []URLParam) []URLParam {
	var out []URLParam
	seen := map[URLParam]bool{}
	for _, p := range in {
		p.Location = strings.ToLower(strings.TrimSpace(p.Location))
		p.Name = strings.TrimSpace(p.Name)
		if !paramLocations[p.Location] || p.Name == "" || len(p.Name) > MaxParamNameBytes || !cleanText(p.Name) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
		if len(out) == MaxURLParams {
			break
		}
	}
	return out
}

// webURL returns raw when it is an http or https URL of at most
// MaxWebURLBytes without control or white-space characters, else "".
func webURL(raw string) (*url.URL, bool) {
	if raw == "" || len(raw) > MaxWebURLBytes || !cleanText(raw) || strings.ContainsAny(raw, " \u00a0") {
		return nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, false
	}
	return u, true
}

// redactedURL drops the user info and fragment of an http(s) URL and every
// query value; with keepNames the query parameter names stay ("?a=&b="),
// otherwise the whole query goes.
func redactedURL(raw string, keepNames bool) string {
	u, ok := webURL(raw)
	if !ok {
		return ""
	}
	u.User, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", false
	var names []string
	if keepNames {
		for _, p := range strings.Split(u.RawQuery, "&") {
			if n, _, _ := strings.Cut(p, "="); n != "" {
				names = append(names, n+"=")
			}
		}
	}
	u.RawQuery = strings.Join(names, "&")
	return u.String()
}

// SanitizeForms bounds the forms of a page: the action is redacted (empty
// when it is not an http(s) URL, so a javascript: action never passes),
// the method is GET or POST and the fields are names only.
func SanitizeForms(in []WebForm) []WebForm {
	var out []WebForm
	for _, f := range in {
		m := strings.ToUpper(strings.TrimSpace(f.Method))
		if m != "POST" {
			m = "GET"
		}
		sf := WebForm{Method: m, Action: redactedURL(f.Action, false), PasswordField: f.PasswordField}
		for _, p := range SanitizeURLParams(f.Params) {
			p.Location = ParamLocationForm
			sf.Params = append(sf.Params, p)
		}
		out = append(out, sf)
		if len(out) == MaxURLForms {
			break
		}
	}
	return out
}

// mediaType returns the lower-cased type/subtype of a Content-Type value,
// without parameters, or "" when it is not one.
func mediaType(ct string) string {
	ct, _, _ = strings.Cut(ct, ";")
	ct = strings.ToLower(strings.TrimSpace(ct))
	if len(ct) > MaxContentTypeBytes || !cleanText(ct) {
		return ""
	}
	t, s, ok := strings.Cut(ct, "/")
	if !ok || !validCookieName(t) || !validCookieName(s) || strings.Contains(s, "/") {
		return ""
	}
	return ct
}

func label(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLabelBytes || !cleanText(s) {
		return ""
	}
	return s
}

// Sanitize bounds every member of a discovered URL that a scanned server
// influences. It reports false when the URL itself is not an http(s) URL
// within the bounds, or the method is not a plain token: the entry is then
// dropped, not repaired. URL and Parent lose their user info, fragment and
// every query value (the names stay), so no value leaves the sensor.
func (u DiscoveredURL) Sanitize() (DiscoveredURL, bool) {
	if _, ok := webURL(u.URL); !ok {
		return DiscoveredURL{}, false
	}
	if u.Method != "" {
		m := strings.ToUpper(strings.TrimSpace(u.Method))
		if len(m) > 10 || !validCookieName(m) {
			return DiscoveredURL{}, false
		}
		u.Method = m
	}
	u.URL = redactedURL(u.URL, true)
	u.Parent = redactedURL(u.Parent, true)
	u.ContentType = mediaType(u.ContentType)
	u.Source, u.Type, u.Extension = label(u.Source), label(u.Type), label(u.Extension)
	u.Params = SanitizeURLParams(u.Params)
	u.Forms = SanitizeForms(u.Forms)
	return u, true
}
