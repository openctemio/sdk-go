package client

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
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
}

// PollCommands retrieves pending commands for this agent.
func (c *Client) PollCommands(ctx context.Context, limit int) ([]Command, error) {
	url := fmt.Sprintf("%s/api/v1/agent/commands?limit=%d", c.baseURL, limit)

	if c.verbose {
		fmt.Printf("[openctem] Polling commands from %s\n", url)
	}

	data, err := c.doRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var commands []Command
	if err := json.Unmarshal(data, &commands); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	if c.verbose {
		fmt.Printf("[openctem] Received %d commands\n", len(commands))
	}

	return commands, nil
}

// GetCommands retrieves pending commands from the server (implements core.CommandClient).
func (c *Client) GetCommands(ctx context.Context) (*core.GetCommandsResponse, error) {
	commands, err := c.PollCommands(ctx, 10)
	if err != nil {
		return nil, err
	}

	// Convert to core.Command pointers
	coreCommands := make([]*core.Command, len(commands))
	for i, cmd := range commands {
		coreCommands[i] = &core.Command{
			ID:       cmd.ID,
			Type:     cmd.Type,
			Priority: cmd.Priority,
			Payload:  cmd.Payload,
		}
	}

	return &core.GetCommandsResponse{
		Commands: coreCommands,
	}, nil
}

// AcknowledgeCommand acknowledges receipt of a command.
func (c *Client) AcknowledgeCommand(ctx context.Context, cmdID string) error {
	url := fmt.Sprintf("%s/api/v1/agent/commands/%s/acknowledge", c.baseURL, cmdID)

	if c.verbose {
		fmt.Printf("[openctem] Acknowledging command %s\n", cmdID)
	}

	_, err := c.doRequest(ctx, "POST", url, nil)
	return err
}

// StartCommand marks a command as started.
func (c *Client) StartCommand(ctx context.Context, cmdID string) error {
	url := fmt.Sprintf("%s/api/v1/agent/commands/%s/start", c.baseURL, cmdID)

	if c.verbose {
		fmt.Printf("[openctem] Starting command %s\n", cmdID)
	}

	_, err := c.doRequest(ctx, "POST", url, nil)
	return err
}

// CompleteCommand marks a command as completed with optional result.
func (c *Client) CompleteCommand(ctx context.Context, cmdID string, result json.RawMessage) error {
	url := fmt.Sprintf("%s/api/v1/agent/commands/%s/complete", c.baseURL, cmdID)

	if c.verbose {
		fmt.Printf("[openctem] Completing command %s\n", cmdID)
	}

	payload := map[string]interface{}{}
	if result != nil {
		payload["result"] = result
	}
	body, _ := json.Marshal(payload)

	_, err := c.doRequest(ctx, "POST", url, body)
	return err
}

// FailCommand marks a command as failed with an error message.
func (c *Client) FailCommand(ctx context.Context, cmdID string, errorMsg string) error {
	url := fmt.Sprintf("%s/api/v1/agent/commands/%s/fail", c.baseURL, cmdID)

	if c.verbose {
		fmt.Printf("[openctem] Failing command %s: %s\n", cmdID, errorMsg)
	}

	payload := map[string]interface{}{
		"error_message": errorMsg,
	}
	body, _ := json.Marshal(payload)

	_, err := c.doRequest(ctx, "POST", url, body)
	return err
}

// ReportCommandResult reports the result of command execution (implements core.CommandClient).
func (c *Client) ReportCommandResult(ctx context.Context, cmdID string, result *core.CommandResult) error {
	if result.Status == "completed" || result.Error == "" {
		resultJSON, _ := json.Marshal(result)
		return c.CompleteCommand(ctx, cmdID, resultJSON)
	}
	return c.FailCommand(ctx, cmdID, result.Error)
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
