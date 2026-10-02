// Package retry is deprecated: the durable outbox (pkg/outbox) replaced it.
//
// The JSON file queue (FileRetryQueue) and its RetryWorker were removed in
// sdk-go v0.8.0. They queued a report only AFTER a failed push, without
// fsync, with a count-based cap, and they were off by default. The outbox
// writes every result before the first send, deletes it only when the
// platform acknowledged it, is crash-safe and encrypted, and caps bytes and
// age. client.Client.EnableOutbox enables it; the client's retry-queue
// methods (EnableRetryQueue, ProcessRetryQueueNow, GetRetryQueueStats, ...)
// still work as deprecated wrappers around it, and reports left in an old
// retry-queue directory are imported on upgrade
// (outbox.Outbox.ImportLegacyRetryQueue).
//
// What remains here are the types those wrappers return and the back-off
// helpers. This package will be removed in sdk-go v0.10.0.
package retry

import (
	"context"
	"time"

	"github.com/openctemio/sdk-go/pkg/ctis"
)

// ReportPusher pushes a report.
//
// Deprecated: see the package documentation.
type ReportPusher interface {
	PushReport(ctx context.Context, report *ctis.Report) error
}

// FingerprintChecker asks the platform which fingerprints it already has.
//
// Deprecated: see the package documentation.
type FingerprintChecker interface {
	CheckFingerprints(ctx context.Context, fingerprints []string) (*FingerprintCheckResult, error)
}

// FingerprintCheckResult is the answer of a fingerprint check.
type FingerprintCheckResult struct {
	Existing []string // Fingerprints that already exist on the server
	Missing  []string // Fingerprints that don't exist on the server
}

// WorkerStats is what client.Client.GetRetryWorkerStats returns.
//
// Deprecated: use client.Client.OutboxStats.
type WorkerStats struct {
	TotalAttempts   int64         `json:"total_attempts"`
	SuccessfulPush  int64         `json:"successful_pushes"`
	FailedAttempts  int64         `json:"failed_attempts"`
	ExhaustedItems  int64         `json:"exhausted_items"`
	TotalDuration   time.Duration `json:"total_duration"`
	LastProcessedAt time.Time     `json:"last_processed_at"`

	IsRunning   bool      `json:"is_running"`
	StartedAt   time.Time `json:"started_at"`
	LastCheckAt time.Time `json:"last_check_at"`
}
