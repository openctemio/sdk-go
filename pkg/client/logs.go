package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// ErrLogsUnsupported: the platform does not take command logs (it does not
// list protov2.FeatureLogs). The sensor keeps its logs local.
var ErrLogsUnsupported = errors.New("the platform does not take command logs")

// commandLogItem is the payload of a KindCommandLog item.
type commandLogItem struct {
	CommandID string                     `json:"command_id"`
	Batch     protov2.CommandLogsRequest `json:"batch"`
}

// SendCommandLogs sends one batch of a command's log lines now
// (POST /commands/{id}/logs). It is ErrLogsUnsupported against a platform
// without the logs feature.
func (c *Client) SendCommandLogs(ctx context.Context, commandID string, batch protov2.CommandLogsRequest) (*protov2.CommandLogsResponse, error) {
	if commandID == "" || len(batch.Lines) == 0 {
		return &protov2.CommandLogsResponse{}, nil
	}
	if !c.PlatformSupports(ctx, protov2.FeatureLogs) {
		return nil, ErrLogsUnsupported
	}
	var out protov2.CommandLogsResponse
	path := protov2.CommandActionPath(url.PathEscape(commandID), protov2.LogsAction)
	if _, err := c.v2JSON(ctx, http.MethodPost, path, batch, &out, nil, 0); err != nil {
		return nil, err
	}
	return &out, nil
}

// QueueCommandLogs hands one batch to the outbox, which delivers it before
// the command's result and keeps it across an outage. Without an outbox it
// sends the batch now. Logs are best effort: a batch the platform refuses
// for good, or a platform without the logs feature, drops the batch; it
// never fails the command.
func (c *Client) QueueCommandLogs(ctx context.Context, commandID string, batch protov2.CommandLogsRequest) error {
	if commandID == "" || len(batch.Lines) == 0 {
		return nil
	}
	if ob := c.Outbox(); ob != nil {
		payload, err := json.Marshal(commandLogItem{CommandID: commandID, Batch: batch})
		if err != nil {
			return err
		}
		if _, err := ob.Enqueue(outbox.Meta{Kind: outbox.KindCommandLog, CommandID: commandID}, payload); err == nil {
			return nil
		}
		// The disk refused it: try once directly.
	}
	_, err := c.SendCommandLogs(ctx, commandID, batch)
	return err
}

// deliverCommandLogs delivers one stored batch. A refusal for good (or a
// platform without the logs feature) drops the batch instead of making a
// dead letter: a log batch must never mark its command's results lost.
func (c *Client) deliverCommandLogs(ctx context.Context, d *outbox.Delivery) error {
	var it commandLogItem
	if err := json.Unmarshal(d.Payload, &it); err != nil || it.CommandID == "" {
		c.logOutbox(c.obLogf, "dropping an unreadable command log batch %s", d.Meta.ID)
		return nil
	}
	_, err := c.SendCommandLogs(ctx, it.CommandID, it.Batch)
	if err == nil || errors.Is(err, ErrLogsUnsupported) {
		return nil
	}
	cerr := classify(err)
	var perm *outbox.PermanentError
	if errors.As(cerr, &perm) {
		c.logOutbox(c.obLogf, "the platform refused log batch %d of command %s; dropped: %v", it.Batch.Seq, it.CommandID, err)
		return nil
	}
	return fmt.Errorf("command logs: %w", cerr)
}
