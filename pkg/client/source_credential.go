package client

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/source"
)

// SourceCredential asks the platform for the credential of a code-scan
// command's repository source (api RFC-091): a short-lived, read-only token
// for that one repository, minted on each call for the sensor holding the
// command's lease. The credential is returned, never logged or stored.
func (c *Client) SourceCredential(ctx context.Context, cmdID string) (*source.Credential, error) {
	if cmdID == "" {
		return nil, errors.New("source credential: no command id")
	}
	var out protov2.SourceCredentialResponse
	path := protov2.PathPrefix + protov2.CommandsPath + "/" + url.PathEscape(cmdID) + "/" + protov2.SourceCredentialAction
	if _, err := c.v2JSON(ctx, http.MethodPost, path, struct{}{}, &out, leaseHeader(c.leases.epoch(cmdID)), 0); err != nil {
		return nil, err
	}
	if out.Password == "" {
		return nil, errors.New("source credential: the platform answered without a credential")
	}
	return &source.Credential{Username: out.Username, Password: out.Password}, nil
}
