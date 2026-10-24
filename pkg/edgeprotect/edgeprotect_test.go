package edgeprotect

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// h builds headers from "Name: value" lines (Set-Cookie may repeat).
func h(lines ...string) http.Header {
	out := http.Header{}
	for _, l := range lines {
		k, v, _ := strings.Cut(l, ": ")
		out.Add(k, v)
	}
	return out
}

// Fixtures are shaped like what each vendor's edge sends: the headers and the
// few words that identify its pages, not the pages themselves.
func TestClassifyVendorFixtures(t *testing.T) {
	cases := []struct {
		name   string
		status int
		header http.Header
		title  string
		body   string
		want   Verdict
	}{
		{"cloudflare managed challenge header", 403,
			h("Server: cloudflare", "Cf-Ray: 8a1b2c3d4e5f-FRA", "Cf-Mitigated: challenge"),
			"Just a moment...", `<script src="/cdn-cgi/challenge-platform/h/b/orchestrate/chl_page/v1"></script>`,
			Verdict{Cloudflare, Challenged, "cloudflare.cf-mitigated"}},
		{"cloudflare interstitial without the header", 503,
			h("Server: cloudflare"), "Just a moment...", `<div id="cf-chl-widget"></div><script>window._cf_chl_opt={};</script> /cdn-cgi/challenge-platform/`,
			Verdict{Cloudflare, Challenged, "cloudflare.managed-challenge-page"}},
		{"cloudflare block page", 403, h("Server: cloudflare", "Cf-Ray: 8a1b2c3d4e5f-FRA"),
			"Attention Required! | Cloudflare", `<h1>Sorry, you have been blocked</h1> Cloudflare Ray ID: 8a1b`,
			Verdict{Cloudflare, Blocked, "cloudflare.block-page"}},
		{"cloudflare firewall rule 1020", 403, h("Server: cloudflare"), "",
			`<title>Access denied</title><span>Error code: 1020</span> Cloudflare`,
			Verdict{Cloudflare, Blocked, "cloudflare.firewall-1020"}},
		{"cloudflare ip ban", 403, h("Server: cloudflare"), "Access denied | example.com used Cloudflare to restrict access",
			`<h1>Error 1006</h1> <p>The owner of this website has banned your IP address</p> Cloudflare Ray ID: 8a`,
			Verdict{Cloudflare, Blocked, "cloudflare.ip-banned"}},
		{"cloudflare rate limit", 429, h("Server: cloudflare", "Retry-After: 30"), "",
			`Error code: 1015 You are being rate limited by Cloudflare`,
			Verdict{Cloudflare, RateLimited, "cloudflare.rate-limit-1015"}},
		{"cloudflare fronted real content", 200, h("Server: cloudflare", "Cf-Ray: 8a-FRA"), "Shop", "<html>hello</html>",
			Verdict{Cloudflare, Fronted, "cloudflare.server"}},
		{"cloudflare browser insights script on a normal page is not a challenge", 200,
			h("Server: cloudflare"), "Shop", `<script defer src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>`,
			Verdict{Cloudflare, Fronted, "cloudflare.server"}},

		{"aws waf challenge", 202, h("X-Amzn-Waf-Action: challenge", "Server: CloudFront"), "", "",
			Verdict{CloudFront, Challenged, "aws-waf.challenge"}},
		{"aws waf captcha", 405, h("X-Amzn-Waf-Action: captcha"), "", "",
			Verdict{CloudFront, Challenged, "aws-waf.captcha"}},
		{"cloudfront waf block", 403, h("X-Cache: Error from cloudfront", "Via: 1.1 abc.cloudfront.net (CloudFront)", "X-Amz-Cf-Id: Xy"),
			"ERROR: The request could not be satisfied", `Request blocked. We can't connect to the server for this app or website at this time.`,
			Verdict{CloudFront, Blocked, "cloudfront.waf-block"}},
		{"cloudfront fronted", 200, h("X-Amz-Cf-Pop: FRA56-C1", "X-Cache: Hit from cloudfront"), "", "ok",
			Verdict{CloudFront, Fronted, "cloudfront.cf-pop"}},

		{"akamai access denied", 403, h("Server: AkamaiGHost", "Mime-Version: 1.0"), "Access Denied",
			`You don't have permission to access "http://shop.example/" on this server.<P>Reference&#32;#18.4a2e3b17.1700000000.1b2c3d4`,
			Verdict{Akamai, Blocked, "akamai.access-denied"}},
		{"akamai sec-cpt challenge", 403, h("Set-Cookie: ak_bmsc=ABC; Path=/", "Server: AkamaiGHost"), "",
			`<div id="sec-if-cpt-container"></div>`, Verdict{Akamai, Challenged, "akamai.sec-cpt-challenge"}},
		{"akamai fronted by header prefix", 200, h("X-Akamai-Transformed: 9 1 0 pmb=mRUM,1"), "", "ok",
			Verdict{Akamai, Fronted, "akamai.x-akamai"}},

		{"fastly waf block", 406, h("X-Served-By: cache-fra-eddf8230045-FRA", "X-Cache: MISS", "Via: 1.1 varnish"), "", "Not Acceptable",
			Verdict{Fastly, Blocked, "fastly.waf-block"}},
		{"fastly request id", 200, h("X-Fastly-Request-Id: 9f1c"), "", "ok", Verdict{Fastly, Fronted, "fastly.request-id"}},
		{"varnish alone is not fastly", 200, h("Via: 1.1 varnish", "X-Cache: HIT"), "", "ok", Verdict{State: Direct}},

		{"azure front door block", 403, h("X-Azure-Ref: 0abc"), "", "<h1>The request is blocked.</h1>",
			Verdict{AzureFD, Blocked, "azure-fd.waf-block"}},
		{"azure front door fronted", 200, h("X-Azure-Ref: 0abc"), "", "ok", Verdict{AzureFD, Fronted, "azure-fd.ref"}},

		{"imperva incident", 403, h("X-Iinfo: 12-345-0 0NNN RT(1 2) q(0 -1 -1 -1) r(0 -1)", "X-Cdn: Imperva"), "",
			`Request unsuccessful. Incapsula incident ID: 1234-5678`, Verdict{Imperva, Blocked, "imperva.incident-block"}},
		{"imperva interruption page", 200, h("X-Iinfo: 1"), "Pardon Our Interruption", "", Verdict{Imperva, Challenged, "imperva.interruption"}},
		{"imperva js interstitial", 200, h("X-Iinfo: 1"), "", `<script src="/_Incapsula_Resource?SWJIYLWA=719d34d31c8e3a6e"></script>`,
			Verdict{Imperva, Challenged, "imperva.js-interstitial"}},
		{"imperva cookie fronted", 200, h("Set-Cookie: incap_ses_123_456=abc; path=/"), "", "ok",
			Verdict{Imperva, Fronted, "imperva.session-cookie"}},

		{"f5 rejected", 200, h("Server: BigIP"), "", `<html><title>Request Rejected</title>The requested URL was rejected. Please consult with your administrator. Your support ID is: 1234567890`,
			Verdict{F5, Blocked, "f5.rejected"}},
		{"f5 cookie fronted", 200, h("Set-Cookie: TS01a1b2c3=0123; Path=/"), "", "ok", Verdict{F5, Fronted, "f5.ts-cookie"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Classify(c.status, c.header, c.title, []byte(c.body))
			if got != c.want {
				t.Fatalf("Classify = %+v, want %+v", got, c.want)
			}
		})
	}
}

// The rule the research states: a challenge or block needs a vendor marker,
// never a bare status.
func TestBareStatusIsNeverAnEdgeDecision(t *testing.T) {
	for _, status := range []int{401, 403, 406, 429, 500, 502, 503} {
		for _, body := range []string{"", "Forbidden", "<title>403 Forbidden</title>nginx", "Access Denied", "Service Unavailable"} {
			v := Classify(status, h("Server: nginx"), "", []byte(body))
			if v.State != Direct {
				t.Errorf("status %d body %q: %+v, want direct", status, body, v)
			}
		}
	}
	// An origin that happens to call its own page "Access Denied" is not Akamai.
	if v := Classify(403, h("Server: Apache"), "Access Denied", []byte("no reference here")); v.State != Direct {
		t.Errorf("plain access denied page: %+v", v)
	}
	// A vendor word in the body without its status or structure is not a block.
	if v := Classify(200, nil, "Blog", []byte("we use cloudflare and attention required is a phrase")); v.State != Direct {
		t.Errorf("blog post about the vendor: %+v", v)
	}
}

func TestStrongestStateWins(t *testing.T) {
	// A fronted answer that carries the challenge header is a challenge.
	v := Classify(403, h("Server: cloudflare", "Cf-Ray: x", "Cf-Mitigated: challenge"), "", nil)
	if v.State != Challenged || !v.State.Stops() {
		t.Fatalf("got %+v", v)
	}
	if Fronted.Stops() || RateLimited.Stops() || Direct.Stops() || !Blocked.Stops() {
		t.Fatal("Stops: only Challenged and Blocked stop a request")
	}
}

func TestTitleReadFromBodyWhenNotGiven(t *testing.T) {
	body := `<html><head><TITLE>Attention Required! | Cloudflare</TITLE></head><body>Cloudflare</body>`
	if v := Classify(403, nil, "", []byte(body)); v.Signal != "cloudflare.block-page" {
		t.Fatalf("got %+v", v)
	}
}

func TestInputsAreBounded(t *testing.T) {
	// A marker past MaxBody is not read.
	late := strings.Repeat("a", MaxBody) + "sorry, you have been blocked cloudflare"
	if v := Classify(403, nil, "", []byte(late)); v.State != Direct {
		t.Fatalf("marker past the bound was read: %+v", v)
	}
	// Huge and hostile inputs finish quickly and decide nothing.
	hdr := http.Header{}
	for i := 0; i < 5000; i++ {
		hdr.Add("X-Junk-"+strings.Repeat("k", i%50), strings.Repeat("v", 100000))
		hdr.Add("Set-Cookie", strings.Repeat("c", 100000))
	}
	start := time.Now()
	v := Classify(403, hdr, strings.Repeat("t", 1<<20), make([]byte, 8<<20))
	if v.State != Direct {
		t.Fatalf("hostile input decided %+v", v)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

func TestRulesAreWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range DefaultRules {
		if r.ID == "" || r.Vendor == "" || len(r.All) == 0 || priority(r.State) == 0 {
			t.Errorf("malformed rule %+v", r)
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if r.State == Challenged || r.State == Blocked {
			// A stopping decision never rests on a status alone or on a
			// marker every page of the vendor carries.
			for _, m := range r.All {
				if m.Header == "" && m.HeaderPrefix == "" && m.Cookie == "" && m.Title == "" && m.Body == "" {
					t.Errorf("rule %s has an empty marker", r.ID)
				}
			}
		}
		for _, m := range r.All {
			if m.Body != strings.ToLower(m.Body) || m.Title != strings.ToLower(m.Title) ||
				m.HeaderContains != strings.ToLower(m.HeaderContains) || m.Cookie != strings.ToLower(m.Cookie) {
				t.Errorf("rule %s: markers are compared lower-case", r.ID)
			}
		}
	}
	// Every vendor has a stopping rule, so no vendor is fronting-only.
	stops := map[string]bool{}
	for _, r := range DefaultRules {
		if r.State.Stops() {
			stops[r.Vendor] = true
		}
	}
	for _, v := range []string{Cloudflare, CloudFront, Akamai, Fastly, AzureFD, Imperva, F5} {
		if !stops[v] {
			t.Errorf("vendor %s has no challenge or block rule", v)
		}
	}
}

func FuzzClassify(f *testing.F) {
	f.Add(403, "Server: cloudflare", "Just a moment...", "challenge-platform")
	f.Add(200, "X-Iinfo: 1", "", "_incapsula_resource")
	f.Fuzz(func(t *testing.T, status int, header, title, body string) {
		v := Classify(status, h(header), title, []byte(body))
		if priority(v.State) == 0 && v.State != Direct {
			t.Fatalf("unknown state %q", v.State)
		}
		if v.State == Direct && (v.Vendor != "" || v.Signal != "") {
			t.Fatalf("direct verdict with a vendor: %+v", v)
		}
	})
}
