// Package edgeprotect recognizes when the answer to a request came from an
// edge protection (a CDN or WAF) in place of the service: a challenge page,
// a block page, a rate limit, or only the edge fronting real content.
//
// The decision is an observation about the edge, never about the service
// behind it: a caller keeps the service's last real response and facts, and
// records the verdict beside them. A challenge or a block needs a marker that
// belongs to one vendor (a vendor header, a vendor error page); a bare 403 or
// 503 is the origin's own answer and is never read as an edge decision. An
// address range or a fronting header alone gives Fronted, never Challenged
// or Blocked.
//
// Classify is pure and bounded: it reads at most MaxBody bytes of the body,
// MaxTitle of the title and MaxHeaderValue of each header value, so a hostile
// response cannot cost more than a fixed amount of work. It never solves a
// challenge, never sends a request and never changes how a request is made:
// the answer to a scan that an edge stops is "the edge stopped it", and what
// follows (allowlisting the scanner at the edge, scanning the origin where it
// is proven to be the tenant's) is cooperative.
//
// The signature table is data (Rules) so a newer table can be shipped without
// a new release of the code that reads it; DefaultRules is the built-in
// floor.
//
// Stability: Beta (docs/STABILITY.md).
package edgeprotect

import (
	"net/http"
	"strings"
)

// State is what the edge did with a request.
type State string

// States, from "no edge seen" to "the edge refused".
const (
	// Direct: no edge marker in the answer.
	Direct State = "direct"
	// Fronted: an edge is in front and passed the request to the service.
	Fronted State = "fronted"
	// Challenged: the edge answered with an interactive or script challenge.
	Challenged State = "challenged"
	// Blocked: the edge refused the request (firewall rule, IP ban, bot
	// block).
	Blocked State = "blocked"
	// RateLimited: the edge throttled the request.
	RateLimited State = "rate_limited"
)

// Stops reports whether the edge stopped the request (challenge or block): the
// answer says nothing about the service behind it.
func (s State) Stops() bool { return s == Challenged || s == Blocked }

// Vendors the built-in rules know.
const (
	Cloudflare = "cloudflare"
	CloudFront = "cloudfront"
	Akamai     = "akamai"
	Fastly     = "fastly"
	AzureFD    = "azure_front_door"
	Imperva    = "imperva"
	F5         = "f5"
)

// Bounds of what Classify reads.
const (
	MaxBody        = 16 << 10
	MaxTitle       = 512
	MaxHeaderValue = 1024
)

// Verdict is the result of Classify.
type Verdict struct {
	// Vendor is the edge vendor ("" when State is Direct).
	Vendor string `json:"vendor,omitempty"`
	State  State  `json:"state"`
	// Signal is the id of the rule that decided ("" when Direct).
	Signal string `json:"signal,omitempty"`
}

// Marker is one condition on the answer; exactly one member is set. Values are
// compared lower-case.
type Marker struct {
	// Header: the header is present (HeaderContains empty) or one of its
	// values contains HeaderContains.
	Header         string `json:"header,omitempty"`
	HeaderContains string `json:"header_contains,omitempty"`
	// HeaderPrefix: some header name starts with it.
	HeaderPrefix string `json:"header_prefix,omitempty"`
	// Cookie: a Set-Cookie sets a cookie whose name starts with it.
	Cookie string `json:"cookie,omitempty"`
	// Title: the page title contains it.
	Title string `json:"title,omitempty"`
	// Body: the first bytes of the body contain it.
	Body string `json:"body,omitempty"`
}

// Rule fires when the status is one of Status (any status when empty), the
// body is at most MaxBodyLen bytes (when set) and every marker matches.
type Rule struct {
	ID         string   `json:"id"`
	Vendor     string   `json:"vendor"`
	State      State    `json:"state"`
	Status     []int    `json:"status,omitempty"`
	MaxBodyLen int      `json:"max_body_len,omitempty"`
	All        []Marker `json:"all"`
}

// input is a response prepared once for every rule.
type input struct {
	status  int
	header  http.Header
	cookies []string
	title   string
	body    string
	bodyLen int
}

func lowerCap(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToLower(s)
}

func prepare(status int, h http.Header, title string, body []byte) *input {
	in := &input{status: status, header: http.Header{}, bodyLen: len(body)}
	for k, vs := range h {
		ck := http.CanonicalHeaderKey(k)
		for i, v := range vs {
			if i == 8 {
				break
			}
			in.header.Add(ck, lowerCap(v, MaxHeaderValue))
		}
	}
	for _, v := range h.Values("Set-Cookie") {
		name, _, _ := strings.Cut(v, "=")
		if len(name) > 128 {
			name = name[:128]
		}
		in.cookies = append(in.cookies, strings.ToLower(strings.TrimSpace(name)))
	}
	b := body
	if len(b) > MaxBody {
		b = b[:MaxBody]
	}
	in.body = strings.ToLower(string(b))
	in.title = lowerCap(strings.TrimSpace(title), MaxTitle)
	if in.title == "" {
		in.title = titleOf(in.body)
	}
	return in
}

// titleOf reads the first <title> of a lower-cased page.
func titleOf(body string) string {
	i := strings.Index(body, "<title")
	if i < 0 {
		return ""
	}
	j := strings.IndexByte(body[i:], '>')
	if j < 0 {
		return ""
	}
	rest := body[i+j+1:]
	k := strings.Index(rest, "</title")
	if k < 0 {
		k = len(rest)
	}
	return lowerCap(strings.TrimSpace(rest[:k]), MaxTitle)
}

func (m Marker) match(in *input) bool {
	switch {
	case m.Header != "":
		vs := in.header.Values(m.Header)
		if len(vs) == 0 {
			return false
		}
		if m.HeaderContains == "" {
			return true
		}
		for _, v := range vs {
			if strings.Contains(v, m.HeaderContains) {
				return true
			}
		}
	case m.HeaderPrefix != "":
		p := strings.ToLower(m.HeaderPrefix)
		for k := range in.header {
			if strings.HasPrefix(strings.ToLower(k), p) {
				return true
			}
		}
	case m.Cookie != "":
		for _, c := range in.cookies {
			if strings.HasPrefix(c, m.Cookie) {
				return true
			}
		}
	case m.Title != "":
		return strings.Contains(in.title, m.Title)
	case m.Body != "":
		return strings.Contains(in.body, m.Body)
	}
	return false
}

func (r *Rule) match(in *input) bool {
	if len(r.All) == 0 {
		return false
	}
	if len(r.Status) > 0 {
		ok := false
		for _, s := range r.Status {
			if s == in.status {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if r.MaxBodyLen > 0 && in.bodyLen > r.MaxBodyLen {
		return false
	}
	for _, m := range r.All {
		if !m.match(in) {
			return false
		}
	}
	return true
}

// priority orders states: the strongest decision wins when several rules
// fire (a challenge header on a fronted answer is a challenge).
func priority(s State) int {
	switch s {
	case Challenged:
		return 4
	case Blocked:
		return 3
	case RateLimited:
		return 2
	case Fronted:
		return 1
	}
	return 0
}

// ClassifyWith decides with the given rules. status is the HTTP status, h the
// response headers (Set-Cookie included), title the page title when the
// caller already has one (otherwise it is read from the body) and body the
// first bytes of the body (a prefix is enough; more than MaxBody is ignored).
// A rule that fires on the strongest state wins; among equals, table order.
func ClassifyWith(rules []Rule, status int, h http.Header, title string, body []byte) Verdict {
	in := prepare(status, h, title, body)
	best := Verdict{State: Direct}
	bp := 0
	for i := range rules {
		r := &rules[i]
		p := priority(r.State)
		if p <= bp || !r.match(in) {
			continue
		}
		best, bp = Verdict{Vendor: r.Vendor, State: r.State, Signal: r.ID}, p
	}
	return best
}

// Classify decides with DefaultRules.
func Classify(status int, h http.Header, title string, body []byte) Verdict {
	return ClassifyWith(DefaultRules, status, h, title, body)
}
