package client

// Self-binding of a signing key (api docs/rfcs/RFC-052-sensor-pairing-and-authorization.md
// §4.8): a client that authenticates with an API key binds the Ed25519 key
// of signer to its sensor. On success the platform has retired every API key
// of the sensor; the caller must sign from then on.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
	"github.com/openctemio/sdk-go/pkg/sensorsig"
)

// BindKey binds signer's key to the sensor this client's API key
// authenticates. On a client that signs with signer's key it confirms an
// earlier bind (the platform answers the identity without a change). The error is a *V2Error for a refusal
// (protov2.ProblemKeyBindRefused, ProblemKeyBindApproval, 401, 404 on a
// platform without the resource).
func (c *Client) BindKey(ctx context.Context, signer *sensorsig.Signer) (*protov2.KeyBindResponse, error) {
	at := time.Now().UTC().Format(time.RFC3339)
	body, err := json.Marshal(protov2.KeyBindRequest{
		PublicKey: base64.RawURLEncoding.EncodeToString(signer.PublicKey()),
		IssuedAt:  at,
		Proof:     base64.RawURLEncoding.EncodeToString(signer.SignBytes(protov2.KeyBindProofMessage(signer.KeyID(), at))),
	})
	if err != nil {
		return nil, err
	}
	data, _, err := c.v2Do(ctx, http.MethodPost, protov2.PathPrefix+protov2.IdentityBindPath, body, "", "")
	if err != nil {
		return nil, err
	}
	var out protov2.KeyBindResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode key bind: %w", err)
	}
	if out.KeyID != signer.KeyID() || out.SensorID == "" {
		return nil, fmt.Errorf("key bind: the platform answered key %q for sensor %q, want key %s", out.KeyID, out.SensorID, signer.KeyID())
	}
	return &out, nil
}
