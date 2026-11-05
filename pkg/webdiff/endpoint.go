package webdiff

import (
	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ResponseKey is the member of an endpoint's io.openctem extension that
// carries a hit's evidence: {"size": <decoded body bytes read>, "hash":
// "<16 hex>"}. LabelsKey carries its labels.
const (
	ResponseKey = "response"
	LabelsKey   = "labels"
)

// Endpoint is the CTIS endpoint of a confirmed hit on origin: method GET,
// the concrete path, status, media type, auth state, source probe (the
// platform sets the source from the capability that ran), and the evidence
// (size and hash of the normalised body) and labels in the io.openctem
// extension. It carries no body, title or header value.
func Endpoint(origin string, h *Hit) ctis.Endpoint {
	e := ctis.Endpoint{
		Origin:      origin,
		Method:      "GET",
		Path:        h.Path,
		Kind:        kindOf(Family(h.ContentType)),
		Source:      ctis.EndpointSourceProbe,
		StatusCode:  h.Status,
		ContentType: h.ContentType,
		Auth:        ctis.EndpointAuth(h.Auth),
	}
	if h.Auth == "" {
		e.Auth = ctis.EndpointAuthUnknown
	}
	e.Extensions.Set(ctis.OpenCTEMNamespace, ResponseKey, map[string]any{"size": h.Size, "hash": h.Hash})
	if len(h.Labels) > 0 {
		e.Extensions.Set(ctis.OpenCTEMNamespace, LabelsKey, append([]string(nil), h.Labels...))
	}
	return e
}

// kindOf is the endpoint kind a content-type family suggests.
func kindOf(family string) ctis.EndpointKind {
	switch family {
	case "html":
		return ctis.EndpointKindPage
	case "json", "xml":
		return ctis.EndpointKindAPI
	case "js":
		return ctis.EndpointKindScript
	}
	return ctis.EndpointKindOther
}
