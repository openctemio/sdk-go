package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// Ensure Client implements core.CommandClient
var _ core.CommandClient = (*Client)(nil)

// Command represents a command from the server.
type Command struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id,omitempty"`
	SourceID       string          `json:"source_id,omitempty"`
	Type           string          `json:"type"`
	Priority       string          `json:"priority"`
	Payload        json.RawMessage `json:"payload,omitempty"`
	Status         string          `json:"status"`
	ErrorMessage   string          `json:"error_message,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	AcknowledgedAt *time.Time      `json:"acknowledged_at,omitempty"`
	StartedAt      *time.Time      `json:"started_at,omitempty"`
	CompletedAt    *time.Time      `json:"completed_at,omitempty"`
	Result         json.RawMessage `json:"result,omitempty"`
	// LeaseEpoch and LeaseExpiresAt are the command's lease (api RFC-035 D6)
	// as of this answer.
	LeaseEpoch     int        `json:"lease_epoch,omitempty"`
	LeaseExpiresAt *time.Time `json:"lease_expires_at,omitempty"`
	// SignedJob is the job signer's envelope for this delivery (claim-N
	// answers; api RFC-040 §5.6).
	SignedJob json.RawMessage `json:"signed_job,omitempty"`
}

// PollCommands retrieves pending commands for this sensor
// (GET /api/v2/sensor/commands).
func (c *Client) PollCommands(ctx context.Context, limit int) ([]Command, error) {
	cmds, err := c.pollCommandsV2(ctx, limit)
	if err != nil {
		return nil, c.v2Missing(err)
	}
	if c.verbose {
		fmt.Printf("[openctem] Received %d commands\n", len(cmds))
	}
	return cmds, nil
}

// DefaultCommandPollLimit is how many commands GetCommands asks for.
const DefaultCommandPollLimit = 10

// GetCommands retrieves pending commands from the server (implements core.CommandClient).
func (c *Client) GetCommands(ctx context.Context) (*core.GetCommandsResponse, error) {
	return c.GetCommandsLimit(ctx, DefaultCommandPollLimit)
}

// GetCommandsLimit retrieves at most limit pending commands (implements
// core.LimitedCommandClient). The CommandPoller passes its free slots, so the
// platform keeps the rest for sensors that can run them now. limit < 1 is 1.
func (c *Client) GetCommandsLimit(ctx context.Context, limit int) (*core.GetCommandsResponse, error) {
	if limit < 1 {
		limit = 1
	}
	commands, err := c.PollCommands(ctx, limit)
	if err != nil {
		return nil, err
	}

	// Convert to core.Command pointers
	coreCommands := make([]*core.Command, len(commands))
	for i, cmd := range commands {
		cc := &core.Command{
			ID:        cmd.ID,
			Type:      cmd.Type,
			Priority:  cmd.Priority,
			Payload:   cmd.Payload,
			CreatedAt: cmd.CreatedAt,
		}
		// Carry the expiry through: the poller skips commands whose
		// ExpiresAt has passed, and dropping it here made every stale
		// command (e.g. one queued while the sensor was offline) run.
		if cmd.ExpiresAt != nil {
			cc.ExpiresAt = *cmd.ExpiresAt
		}
		cc.LeaseEpoch = cmd.LeaseEpoch
		cc.SignedJob = cmd.SignedJob
		// Claim-N: the platform already claimed it for this sensor.
		cc.Claimed = cmd.Status == "acknowledged"
		if cmd.LeaseExpiresAt != nil {
			cc.LeaseExpiresAt = *cmd.LeaseExpiresAt
		}
		coreCommands[i] = cc
	}

	return &core.GetCommandsResponse{
		Commands: coreCommands,
	}, nil
}

// AcknowledgeCommand claims a command (POST .../commands/{id}/claim).
func (c *Client) AcknowledgeCommand(ctx context.Context, cmdID string) error {
	return c.commandV2(ctx, cmdID, protov2.ClaimAction, nil, c.maxRetries)
}

// StartCommand marks a command as started.
func (c *Client) StartCommand(ctx context.Context, cmdID string) error {
	return c.commandV2(ctx, cmdID, protov2.StartAction, nil, c.maxRetries)
}

// CompleteCommand marks a command as completed with optional result.
func (c *Client) CompleteCommand(ctx context.Context, cmdID string, result json.RawMessage) error {
	return c.completeCommand(ctx, cmdID, result, c.maxRetries)
}

func (c *Client) completeCommand(ctx context.Context, cmdID string, result json.RawMessage, retries int) error {
	return c.commandV2(ctx, cmdID, protov2.CompleteAction, protov2.CompleteRequest{Result: result}, retries)
}

// FailCommand marks a command as failed with an error message.
func (c *Client) FailCommand(ctx context.Context, cmdID string, errorMsg string) error {
	return c.failCommand(ctx, cmdID, errorMsg, nil, c.maxRetries)
}

// failCommand fails a command. A policy refusal goes along structured
// (protov2.FailRequest.Refusal) when the platform lists FeatureRefusal; the
// error message carries the text form either way.
func (c *Client) failCommand(ctx context.Context, cmdID string, errorMsg string, refusal *core.Refusal, retries int) error {
	req := protov2.FailRequest{ErrorMessage: errorMsg}
	if refusal != nil && c.PlatformSupports(ctx, protov2.FeatureRefusal) {
		req.Refusal = &protov2.Refusal{Layer: refusal.Layer, Rule: refusal.Rule, Detail: refusal.Detail}
	}
	return c.commandV2(ctx, cmdID, protov2.FailAction, req, retries)
}

// ReleaseCommand hands a claimed command back to the platform, which
// returns it to pending (unpinned) so any sensor can run it at once
// (implements core.ReleasingCommandClient). On a platform from before the
// release transition the command is failed with "released: <reason>"
// instead, so it does not wait for a timeout.
func (c *Client) ReleaseCommand(ctx context.Context, cmdID, reason string) error {
	if len(reason) > protov2.MaxReleaseReasonLen {
		reason = reason[:protov2.MaxReleaseReasonLen]
	}
	err := c.transitionV2(ctx, cmdID, protov2.ReleaseAction, protov2.ReleaseRequest{Reason: reason}, nil, nil, c.maxRetries)
	if err == nil || !isRouteMissing(err) {
		if err == nil || IsCommandGone(err) {
			c.leases.forget(cmdID)
		}
		return err
	}
	return c.failCommand(ctx, cmdID, "released: "+reason, nil, c.maxRetries)
}

var _ core.ReleasingCommandClient = (*Client)(nil)

// commandV2 applies a command transition (api RFC-029 §4.4).
func (c *Client) commandV2(ctx context.Context, cmdID, action string, body any, retries int) error {
	if c.verbose {
		fmt.Printf("[openctem] Command %s: %s (v2)\n", cmdID, action)
	}
	// Claim and start answer the command with the lease epoch it is now
	// held under; complete and fail echo it (api RFC-035 D6).
	var answer protov2.Command
	var extra http.Header
	epoch := 0
	switch action {
	case protov2.CompleteAction, protov2.FailAction:
		epoch = c.leases.epoch(cmdID)
		extra = leaseHeader(epoch)
	}
	err := c.transitionV2(ctx, cmdID, action, body, &answer, extra, retries)
	if isRouteMissing(err) {
		return c.v2Missing(err)
	}
	switch action {
	case protov2.ClaimAction, protov2.StartAction:
		if err == nil {
			c.leases.record(cmdID, answer.LeaseEpoch)
		} else if IsCommandGone(err) {
			c.leases.forget(cmdID)
		}
	case protov2.CompleteAction, protov2.FailAction:
		if err == nil || IsCommandGone(err) {
			c.leases.forget(cmdID)
		}
		err = leaseLost(action, epoch, err)
	}
	return err
}

// ReportCommandResult reports the result of command execution (implements
// core.CommandClient). With the outbox enabled the result is stored and
// delivered after every report of the same command was accepted (or
// refused, which turns a "completed" result into "failed"); it returns once
// the result was delivered, or after OutboxConfig.SyncWait (or at once
// while the platform is unreachable) with the result safe on disk.
//
// Waiting for the delivery matters for dispatch (api RFC-030): the
// platform counts the command as held by this sensor until its complete
// arrives, so a poller that freed the slot and polled first was refused
// (no free capacity) or, before the platform knew the sensor's capacity,
// handed one command too many.
func (c *Client) ReportCommandResult(ctx context.Context, cmdID string, result *core.CommandResult) error {
	if ob := c.Outbox(); ob != nil {
		if tk, err := c.enqueueCommandResult(ob, cmdID, result); err == nil {
			return c.awaitResultTicket(ctx, tk)
		} else {
			c.logOutbox(c.obLogf, "cannot store the result of command %s (%v); reporting it directly", cmdID, err)
		}
	}
	return c.reportCommandResult(ctx, cmdID, result, c.maxRetries)
}

// reportCommandResultOnce reports a result with a single attempt (the
// outbox retries).
func (c *Client) reportCommandResultOnce(ctx context.Context, cmdID string, result *core.CommandResult) error {
	return c.reportCommandResult(ctx, cmdID, result, 0)
}

func (c *Client) reportCommandResult(ctx context.Context, cmdID string, result *core.CommandResult, retries int) error {
	if result.Status == "completed" || result.Error == "" {
		resultJSON, _ := json.Marshal(result)
		return c.completeCommand(ctx, cmdID, resultJSON, retries)
	}
	return c.failCommand(ctx, cmdID, result.Error, result.Refusal, retries)
}

// ReportCommandProgress reports progress of command execution.
func (c *Client) ReportCommandProgress(ctx context.Context, cmdID string, progress int, message string) error {
	// Note: Progress reporting is not supported in current backend API
	// This is a placeholder for future implementation
	if c.verbose {
		fmt.Printf("[openctem] Progress for command %s: %d%% - %s\n", cmdID, progress, message)
	}
	return nil
}
