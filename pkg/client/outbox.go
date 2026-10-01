package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/outbox"
	protov2 "github.com/openctemio/sdk-go/pkg/sensorproto/v2"
)

// OutboxConfig enables the durable outbox (pkg/outbox) on a client. With it,
// every report and command result is written to disk before the first send
// and deleted only after the platform acknowledged it.
type OutboxConfig struct {
	// Dir is the outbox directory (required). The sensor's default is
	// /var/lib/openctem/outbox.
	Dir string
	// KeyFile is the encryption key file (default <Dir>/outbox.key).
	KeyFile string
	// MaxBytes caps the bytes on disk (default 1 GiB, and never more than
	// half of the space the outbox could use).
	MaxBytes int64
	// MaxAge evicts items older than this (default 7 days).
	MaxAge time.Duration
	// Concurrency is 1 (default) or 2.
	Concurrency int
	// SyncWait is how long PushFindings/PushAssets wait for the first
	// delivery before answering "queued" (default 30s; negative: do not
	// wait).
	SyncWait time.Duration
	// LegacyRetryQueueDir is a pre-outbox retry-queue directory whose
	// reports are imported once (default ~/.openctem/retry-queue; "-" skips
	// the import).
	LegacyRetryQueueDir string
	// Logf receives the outbox's log lines (default: stderr with a
	// timestamp).
	Logf func(format string, args ...any)
	// OnEvict is told when the caps dropped results (turn it into an alert).
	OnEvict func(evicted []outbox.Meta, reason string)
}

// DefaultOutboxSyncWait is OutboxConfig.SyncWait's default.
const DefaultOutboxSyncWait = 30 * time.Second

// DefaultLegacyRetryQueueDir is where pre-outbox SDKs kept their retry queue.
func DefaultLegacyRetryQueueDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".openctem", "retry-queue")
}

// EnableOutbox opens the outbox and starts delivering from it in the
// background until Close. Reports left in an old retry-queue directory are
// imported first.
func (c *Client) EnableOutbox(cfg OutboxConfig) error {
	ob, err := outbox.Open(outbox.Config{
		Dir:         cfg.Dir,
		KeyFile:     cfg.KeyFile,
		MaxBytes:    cfg.MaxBytes,
		MaxAge:      cfg.MaxAge,
		Concurrency: cfg.Concurrency,
		Logf:        cfg.Logf,
		OnEvict:     cfg.OnEvict,
	})
	if err != nil {
		return err
	}
	c.obMu.Lock()
	if c.ob != nil {
		c.obMu.Unlock()
		_ = ob.Close()
		return errors.New("outbox already enabled")
	}
	legacy := cfg.LegacyRetryQueueDir
	if legacy == "" {
		legacy = DefaultLegacyRetryQueueDir()
	}
	if legacy != "-" {
		if _, err := ob.ImportLegacyRetryQueue(legacy); err != nil {
			c.logOutbox(cfg.Logf, "importing the old retry queue %s: %v", legacy, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	c.ob, c.obCancel, c.obDone = ob, cancel, done
	c.obSyncWait = cfg.SyncWait
	if c.obSyncWait == 0 {
		c.obSyncWait = DefaultOutboxSyncWait
	}
	c.obLogf = cfg.Logf
	c.obMu.Unlock()
	go func() {
		defer close(done)
		_ = ob.Run(ctx, c)
	}()
	return nil
}

func (c *Client) logOutbox(logf func(string, ...any), format string, args ...any) {
	if logf != nil {
		logf(format, args...)
		return
	}
	fmt.Fprintf(os.Stderr, "[outbox] "+format+"\n", args...)
}

// Outbox returns the client's outbox, or nil when it is not enabled.
func (c *Client) Outbox() *outbox.Outbox {
	c.obMu.Lock()
	defer c.obMu.Unlock()
	return c.ob
}

// OutboxStats returns the outbox's state; ok is false without an outbox.
func (c *Client) OutboxStats() (outbox.Stats, bool) {
	ob := c.Outbox()
	if ob == nil {
		return outbox.Stats{}, false
	}
	return ob.Stats(), true
}

// FlushOutbox delivers what can be delivered now and returns when nothing is
// left that could be sent right away (or ctx ends). A one-shot run calls it
// before exiting.
func (c *Client) FlushOutbox(ctx context.Context) error {
	ob := c.Outbox()
	if ob == nil {
		return nil
	}
	ob.Wake()
	return ob.Wait(ctx)
}

// closeOutbox stops delivery and releases the outbox directory.
func (c *Client) closeOutbox() error {
	c.obMu.Lock()
	ob, cancel, done := c.ob, c.obCancel, c.obDone
	c.ob, c.obCancel, c.obDone = nil, nil, nil
	c.obMu.Unlock()
	if ob == nil {
		return nil
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
	return ob.Close()
}

// enqueueReport writes a report to the outbox and waits up to SyncWait for
// its first delivery.
func (c *Client) enqueueReport(ctx context.Context, ob *outbox.Outbox, report *ctis.Report, assetsOnly bool) (*core.PushResult, error) {
	payload, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	meta := outbox.Meta{Kind: outbox.KindReport, CommandID: core.CommandIDFromContext(ctx)}
	if assetsOnly {
		meta.Attrs = map[string]string{outbox.AttrAssetsOnly: "true"}
	}
	tk, err := ob.Enqueue(meta, payload)
	if err != nil {
		// The disk refused it (full, read-only, too large): send it now
		// rather than drop it.
		c.logOutbox(c.obLogf, "cannot store a report in the outbox (%v); sending it directly", err)
		return c.pushReportDirect(ctx, report, assetsOnly)
	}
	return c.awaitTicket(ctx, tk)
}

func (c *Client) awaitTicket(ctx context.Context, tk *outbox.Ticket) (*core.PushResult, error) {
	queued := &core.PushResult{
		Success:  true,
		Queued:   true,
		ReportID: tk.Meta.ReportID,
		Message:  "stored in the outbox; it is delivered when the platform accepts it",
	}
	if c.obSyncWait < 0 {
		return queued, nil
	}
	timer := time.NewTimer(c.obSyncWait)
	defer timer.Stop()
	select {
	case r := <-tk.Done():
		switch {
		case r.Delivered:
			if pr, ok := r.Value.(*core.PushResult); ok {
				return pr, nil
			}
			return &core.PushResult{Success: true, ReportID: tk.Meta.ReportID}, nil
		case r.Dead != nil:
			return nil, &RefusedError{DeadLetter: *r.Dead}
		default:
			return nil, fmt.Errorf("report %s was evicted from the outbox before delivery", tk.Meta.ReportID)
		}
	case <-timer.C:
		return queued, nil
	case <-ctx.Done():
		return queued, nil
	}
}

// RefusedError says the platform refused a report for good; it is in the outbox's
// dead-letter folder.
type RefusedError struct {
	DeadLetter outbox.DeadLetter
}

func (e *RefusedError) Error() string {
	if e.DeadLetter.Status != 0 {
		return fmt.Sprintf("the platform refused report %s (HTTP %d): %s", e.DeadLetter.Meta.ReportID, e.DeadLetter.Status, e.DeadLetter.Reason)
	}
	return fmt.Sprintf("report %s refused: %s", e.DeadLetter.Meta.ReportID, e.DeadLetter.Reason)
}

// commandResultItem is the payload of a KindCommandResult item.
type commandResultItem struct {
	CommandID string             `json:"command_id"`
	Result    core.CommandResult `json:"result"`
}

// enqueueCommandResult stores a command result behind the command's reports.
func (c *Client) enqueueCommandResult(ob *outbox.Outbox, cmdID string, result *core.CommandResult) error {
	payload, err := json.Marshal(commandResultItem{CommandID: cmdID, Result: *result})
	if err != nil {
		return err
	}
	_, err = ob.Enqueue(outbox.Meta{Kind: outbox.KindCommandResult, CommandID: cmdID}, payload)
	return err
}

var _ outbox.Deliverer = (*Client)(nil)

// Deliver implements outbox.Deliverer: one attempt at one item, classified
// for the outbox (RFC-026 §3.8 retry table).
func (c *Client) Deliver(ctx context.Context, d *outbox.Delivery) (any, error) {
	switch d.Meta.Kind {
	case outbox.KindReport:
		return c.deliverReport(ctx, d)
	case outbox.KindCommandResult:
		return nil, c.deliverCommandResult(ctx, d)
	default:
		return nil, outbox.Permanent(0, fmt.Sprintf("item kind %q is not delivered by the API client", d.Meta.Kind), nil, nil)
	}
}

func (c *Client) deliverReport(ctx context.Context, d *outbox.Delivery) (any, error) {
	var r ctis.Report
	if err := json.Unmarshal(d.Payload, &r); err != nil {
		return nil, outbox.Permanent(0, "the stored payload is not a CTIS report", nil, err)
	}
	assetsOnly := d.Meta.Attrs[outbox.AttrAssetsOnly] == "true"
	if assetsOnly {
		r.Findings = nil
	}
	useV2, _, err := c.resultsProtocol(ctx)
	if err != nil {
		if errors.Is(err, ErrV2Unsupported) {
			return nil, outbox.Permanent(0, err.Error(), nil, err)
		}
		return nil, classify(err)
	}
	if useV2 {
		var prog *V2Progress
		if len(d.State.Progress) > 0 {
			var p V2Progress
			if json.Unmarshal(d.State.Progress, &p) == nil {
				prog = &p
			}
		}
		st, err := c.PushResultsV2(ctx, &r, &V2PushOptions{
			ReportID:  d.Meta.ReportID,
			CommandID: d.Meta.CommandID,
			Progress:  prog,
			OnProgress: func(p V2Progress) error {
				b, err := json.Marshal(p)
				if err != nil {
					return err
				}
				return d.SaveProgress(b)
			},
			Logf: c.v2Logf(),
		})
		if err == nil {
			return v2PushResult(st), nil
		}
		var ve *V2Error
		switch {
		case errors.Is(err, ErrV2NoTool):
			return nil, outbox.Permanent(0, err.Error(), nil, err)
		case errors.As(err, &ve) && c.protocol == ProtocolAuto && ve.routeMissing():
			c.forceV1(false) // the platform lost its v2 routes: use v1 now
		case errors.As(err, &ve) && c.protocol == ProtocolAuto && ve.ProblemName() == protov2.ProblemScopeDenied:
			c.forceV1(true) // this sensor may not use v2 (platform sensor)
		default:
			return nil, classify(err)
		}
	}
	// Protocol v1. A replay after a lost response is deduplicated by the
	// server's finding fingerprints: best effort, not exact.
	res, err := c.pushReportV1(ctx, &r, assetsOnly, 0)
	if err != nil {
		return nil, classify(err)
	}
	return res, nil
}

func v2PushResult(st *protov2.Status) *core.PushResult {
	return &core.PushResult{
		Success:         true,
		Message:         fmt.Sprintf("accepted (report %s, %s)", st.ReportID, st.State),
		ReportID:        st.ReportID,
		FindingsCreated: st.Accepted.Findings,
		AssetsCreated:   st.Accepted.Assets,
	}
}

func (c *Client) v2Logf() func(string, ...any) {
	return func(format string, args ...any) { c.logOutbox(c.obLogf, format, args...) }
}

func (c *Client) deliverCommandResult(ctx context.Context, d *outbox.Delivery) error {
	var it commandResultItem
	if err := json.Unmarshal(d.Payload, &it); err != nil || it.CommandID == "" {
		return outbox.Permanent(0, "the stored payload is not a command result", nil, err)
	}
	res := it.Result
	if dl, ok := d.Outbox().DeadLetterForCommand(it.CommandID); ok && res.Status != "failed" {
		// The command ran, but the platform refused its results: it must
		// not look like a clean, complete scan.
		res.Status = "failed"
		res.Error = "the platform refused the command's results: " + dl.Reason
	}
	if err := c.reportCommandResultOnce(ctx, it.CommandID, &res); err != nil {
		return classify(err)
	}
	return nil
}

// classify maps a send error to the outbox's classes.
func classify(err error) error {
	var ve *V2Error
	if errors.As(err, &ve) {
		switch {
		case ve.Status == http.StatusUnauthorized:
			return outbox.Unauthorized(err)
		case ve.Transient():
			if ve.RetryAfter > 0 {
				return outbox.RetryAfter(err, ve.RetryAfter)
			}
			return err
		default:
			var problem []byte
			reason := fmt.Sprintf("HTTP %d", ve.Status)
			if ve.Problem != nil {
				problem, _ = json.Marshal(ve.Problem)
				reason = string(ve.Problem.Name()) + ": " + ve.Problem.Detail
			} else if ve.Body != "" {
				reason = truncateForError(ve.Body, 512)
			}
			return outbox.Permanent(ve.Status, reason, problem, err)
		}
	}
	var he *HTTPError
	if errors.As(err, &he) {
		switch {
		case he.StatusCode == http.StatusUnauthorized || he.StatusCode == http.StatusForbidden:
			// v1 answers both for a key it no longer accepts (core.AuthGate
			// treats them alike).
			return outbox.Unauthorized(err)
		case he.StatusCode == http.StatusTooManyRequests || he.StatusCode == http.StatusServiceUnavailable:
			return outbox.RetryAfter(err, he.RetryAfter)
		case he.StatusCode >= 500:
			return err
		case he.StatusCode >= 400:
			return outbox.Permanent(he.StatusCode, truncateForError(he.Body, 512), nil, err)
		}
	}
	return err // network and anything unknown: transient
}
