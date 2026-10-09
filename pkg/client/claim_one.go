package client

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ClaimCommand claims the command with id for this sensor and returns it,
// payload included (POST .../commands/{id}/claim answers the command): a
// sensor started to run one given job (sensorkit Kit.RunJob). The platform
// refuses a command of another tenant, one another sensor holds, and one
// that is no longer pending; a replay of this sensor's own claim answers
// the command again. The command keeps the answer's payload bytes as
// received and its signed job (api RFC-040 §5.6); the CommandPoller claims
// through it when it verifies job signatures (core.CommandClaimer).
func (c *Client) ClaimCommand(ctx context.Context, id string) (*core.Command, error) {
	if _, err := uuid.Parse(id); err != nil {
		return nil, fmt.Errorf("claim: %q is not a command id", id)
	}
	var answer protov2.Command
	err := c.transitionV2(ctx, id, protov2.ClaimAction, nil, &answer, nil, c.maxRetries)
	if isRouteMissing(err) {
		return nil, c.v2Missing(err)
	}
	if err != nil {
		if IsCommandGone(err) {
			c.leases.forget(id)
		}
		return nil, err
	}
	c.leases.record(id, answer.LeaseEpoch)
	cmd := &core.Command{ID: answer.ID, Type: answer.Type, Priority: answer.Priority, Payload: answer.Payload,
		CreatedAt: answer.CreatedAt, LeaseEpoch: answer.LeaseEpoch, Claimed: true, SignedJob: answer.SignedJob}
	if answer.ExpiresAt != nil {
		cmd.ExpiresAt = *answer.ExpiresAt
	}
	if answer.LeaseExpiresAt != nil {
		cmd.LeaseExpiresAt = *answer.LeaseExpiresAt
	}
	if cmd.ID != id {
		return nil, fmt.Errorf("claim: the platform answered command %q for %q", cmd.ID, id)
	}
	return cmd, nil
}

var _ core.CommandClaimer = (*Client)(nil)
