package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ToolCredentials asks the platform, for one task of a scan command's tool,
// for the third-party source keys the command's organization stored for
// that tool, under the command's lease. The values are returned, never
// logged or stored. A platform without the route answers
// core.ErrToolCredentialsUnsupported.
func (c *Client) ToolCredentials(ctx context.Context, cmdID, tool string) (*core.ToolCredentialSet, error) {
	if cmdID == "" || tool == "" {
		return nil, errors.New("tool credentials: no command or tool")
	}
	var out protov2.ToolCredentialsResponse
	path := protov2.PathPrefix + protov2.CommandsPath + "/" + url.PathEscape(cmdID) + "/" + protov2.ToolCredentialsAction
	if _, err := c.v2JSON(ctx, http.MethodPost, path, protov2.ToolCredentialsRequest{Tool: tool}, &out,
		leaseHeader(c.leases.epoch(cmdID)), 2); err != nil {
		if routeUnknown(err) {
			return nil, core.ErrToolCredentialsUnsupported
		}
		return nil, err
	}
	if len(out.Credentials) > protov2.MaxToolCredentials {
		return nil, fmt.Errorf("tool credentials: the platform sent %d credentials (at most %d)", len(out.Credentials), protov2.MaxToolCredentials)
	}
	set := &core.ToolCredentialSet{Values: make(map[string]string, len(out.Credentials)), LocalFallback: out.LocalFallback}
	for _, cr := range out.Credentials {
		if cr.Name != "" && cr.Value != "" {
			set.Values[cr.Name] = cr.Value
		}
	}
	return set, nil
}

// routeUnknown reports a 404 or 405 that is not a problem document of the
// v2 protocol: the platform does not serve the route at all (a refusal of
// the command is a command-not-found problem).
func routeUnknown(err error) bool {
	var ve *V2Error
	if !errors.As(err, &ve) {
		return false
	}
	return (ve.Status == http.StatusNotFound || ve.Status == http.StatusMethodNotAllowed) && ve.Problem == nil
}
