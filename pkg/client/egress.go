package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/openctemio/sdk-go/pkg/sensorkit/egress/upstream"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// EgressReport sends a job's per-endpoint proxy signals (best-effort, at
// most protov2.MaxEgressReportEndpoints endpoints), under the command's
// lease (its epoch inside the body).
func (c *Client) EgressReport(ctx context.Context, cmdID string, r upstream.Report) error {
	if cmdID == "" || r.PoolID == "" {
		return errors.New("egress report: no command or pool id")
	}
	epoch := c.leases.epoch(cmdID)
	body := protov2.EgressReport{LeaseEpoch: int64(epoch), PoolID: r.PoolID, Endpoints: make([]protov2.EgressEndpointReport, 0, len(r.Endpoints))}
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
	_, err := c.v2JSON(ctx, http.MethodPost, path, body, nil, leaseHeader(epoch), 0)
	return err
}
