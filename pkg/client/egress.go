package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// EgressCredentials asks the platform for the credentials of the proxy pool
// a scan command's egress block names, under the command's lease. The
// credentials are returned, never logged or stored.
func (c *Client) EgressCredentials(ctx context.Context, cmdID, poolID string) ([]upstream.Credential, error) {
	if cmdID == "" || poolID == "" {
		return nil, errors.New("egress credentials: no command or pool id")
	}
	var out protov2.EgressCredentialsResponse
	path := protov2.PathPrefix + protov2.CommandsPath + "/" + url.PathEscape(cmdID) + "/" + protov2.EgressCredentialsAction
	if _, err := c.v2JSON(ctx, http.MethodPost, path, protov2.EgressCredentialsRequest{PoolID: poolID}, &out,
		leaseHeader(c.leases.epoch(cmdID)), 0); err != nil {
		return nil, err
	}
	creds := make([]upstream.Credential, 0, len(out.Credentials))
	for _, cr := range out.Credentials {
		creds = append(creds, upstream.Credential{EndpointID: cr.EndpointID, Username: cr.Username, Password: cr.Password})
	}
	return creds, nil
}

// EgressReport sends a job's per-endpoint proxy signals (best-effort, at
// most protov2.MaxEgressReportEndpoints endpoints), under the command's
// lease.
func (c *Client) EgressReport(ctx context.Context, cmdID string, r upstream.Report) error {
	if cmdID == "" || r.PoolID == "" {
		return errors.New("egress report: no command or pool id")
	}
	body := protov2.EgressReport{PoolID: r.PoolID, Endpoints: make([]protov2.EgressEndpointReport, 0, len(r.Endpoints))}
	for i, e := range r.Endpoints {
		if i == protov2.MaxEgressReportEndpoints {
			break
		}
		last := e.LastError
		if len(last) > protov2.MaxEgressLastError {
			last = last[:protov2.MaxEgressLastError]
		}
		body.Endpoints = append(body.Endpoints, protov2.EgressEndpointReport{EndpointID: e.EndpointID, OK: e.OK,
			ProxyDown: e.ProxyDown, ProxyAuth: e.ProxyAuth, TargetUnreachable: e.TargetUnreachable,
			TargetRefused: e.TargetRefused, HandshakeMsP50: e.HandshakeMsP50, HandshakeMsP95: e.HandshakeMsP95,
			LastError: last})
	}
	path := protov2.PathPrefix + protov2.CommandsPath + "/" + url.PathEscape(cmdID) + "/" + protov2.EgressReportAction
	_, err := c.v2JSON(ctx, http.MethodPost, path, body, nil, leaseHeader(c.leases.epoch(cmdID)), 0)
	return err
}
