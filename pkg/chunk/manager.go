package chunk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/outbox"
)

// Uploader is the interface for uploading chunks.
type Uploader interface {
	// UploadChunk uploads a single chunk.
	UploadChunk(ctx context.Context, data *ChunkData) error
}

// Outbox item attributes of a chunk.
const (
	attrReportID    = "chunk_report_id"
	attrChunkIndex  = "chunk_index"
	attrTotalChunks = "chunk_total"
)

// Manager splits large reports into protocol v1 chunks and uploads them
// from the durable outbox (pkg/outbox): every chunk is on disk before the
// first upload and removed only when the platform accepted it, so a crash
// or restart resumes where it stopped. (Before sdk-go v0.8.0 the chunks
// lived in a SQLite database; see Config.DatabasePath.)
type Manager struct {
	cfg      *Config
	ob       *outbox.Outbox
	splitter *Splitter
	uploader Uploader

	mu      sync.RWMutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	reports map[string]*Report

	// Callbacks
	onProgress func(*Progress)
	onComplete func(reportID string)
	onError    func(reportID string, err error)

	verbose bool
}

// NewManager creates a chunk manager and opens its outbox.
func NewManager(cfg *Config) (*Manager, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	dir := cfg.outboxDir()
	if cfg.DatabasePath != "" {
		if fi, err := os.Stat(cfg.DatabasePath); err == nil && fi.Size() > 0 {
			fmt.Fprintf(os.Stderr, "[chunk] %s is the chunk database of an SDK before v0.8.0; chunks still pending in it are not uploaded any more (chunks now live in %s). Delete it once it is not needed.\n",
				cfg.DatabasePath, dir)
		}
	}
	ob, err := outbox.Open(outbox.Config{
		Dir:      dir,
		MaxBytes: int64(cfg.MaxStorageMB) << 20,
	})
	if err != nil {
		return nil, fmt.Errorf("init chunk outbox: %w", err)
	}
	m := &Manager{
		cfg:      cfg,
		ob:       ob,
		splitter: NewSplitter(cfg),
		reports:  map[string]*Report{},
	}
	m.recoverReports()
	return m, nil
}

// recoverReports rebuilds the progress of reports whose chunks a previous
// process left in the outbox.
func (m *Manager) recoverReports() {
	for _, meta := range m.ob.Pending() {
		if meta.Kind != outbox.KindChunk {
			continue
		}
		id := meta.Attrs[attrReportID]
		total, _ := strconv.Atoi(meta.Attrs[attrTotalChunks])
		r := m.reports[id]
		if r == nil {
			r = &Report{ID: id, TotalChunks: total, Status: ReportStatusPending, CreatedAt: meta.CreatedAt, UpdatedAt: meta.CreatedAt}
			m.reports[id] = r
		}
	}
	for id, r := range m.reports {
		pending := 0
		for _, meta := range m.ob.Pending() {
			if meta.Attrs[attrReportID] == id {
				pending++
			}
		}
		// Chunks of this report not in the outbox any more were uploaded.
		r.CompletedChunks = max(0, r.TotalChunks-pending)
	}
}

// SetUploader configures the uploader.
func (m *Manager) SetUploader(uploader Uploader) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uploader = uploader
}

// SetCallbacks sets the callback functions.
func (m *Manager) SetCallbacks(onProgress func(*Progress), onComplete func(string), onError func(string, error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onProgress = onProgress
	m.onComplete = onComplete
	m.onError = onError
}

// SetVerbose enables verbose logging.
func (m *Manager) SetVerbose(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verbose = v
}

// NeedsChunking checks if a report needs to be chunked.
func (m *Manager) NeedsChunking(report *ctis.Report) bool {
	return m.splitter.NeedsChunking(report)
}

// SubmitReport splits a report into chunks and stores them durably in the
// outbox. It returns once every chunk is on disk.
func (m *Manager) SubmitReport(_ context.Context, report *ctis.Report) (*Report, error) {
	chunkDataList, err := m.splitter.Split(report)
	if err != nil {
		return nil, fmt.Errorf("split report: %w", err)
	}
	reportID := chunkDataList[0].ReportID
	now := time.Now()
	originalData, err := json.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	r := &Report{
		ID:                    reportID,
		OriginalFindingsCount: len(report.Findings),
		OriginalAssetsCount:   len(report.Assets),
		OriginalSize:          len(originalData),
		TotalChunks:           len(chunkDataList),
		Status:                ReportStatusPending,
		CompressionAlgo:       "zstd",
		CreatedAt:             now,
		UpdatedAt:             now,
		Metadata:              &Metadata{ScanID: reportID},
	}
	if report.Tool != nil {
		r.Metadata.ToolName = report.Tool.Name
		r.Metadata.ToolVersion = report.Tool.Version
	}
	m.mu.Lock()
	m.reports[reportID] = r
	m.mu.Unlock()

	before := m.ob.Stats().PendingBytes
	for i, cd := range chunkDataList {
		data, err := json.Marshal(cd)
		if err != nil {
			return nil, fmt.Errorf("marshal chunk %d: %w", i, err)
		}
		if _, err := m.ob.Enqueue(outbox.Meta{
			Kind: outbox.KindChunk,
			Attrs: map[string]string{
				attrReportID:    reportID,
				attrChunkIndex:  strconv.Itoa(i),
				attrTotalChunks: strconv.Itoa(len(chunkDataList)),
			},
		}, data); err != nil {
			return nil, fmt.Errorf("store chunk %d: %w", i, err)
		}
	}
	m.mu.Lock()
	r.CompressedSize = int(max(0, m.ob.Stats().PendingBytes-before))
	m.mu.Unlock()
	if m.isVerbose() {
		fmt.Printf("[chunk] Report %s queued: %d chunks, %d bytes -> %d bytes\n",
			reportID, len(chunkDataList), r.OriginalSize, r.CompressedSize)
	}
	return r, nil
}

func (m *Manager) isVerbose() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.verbose
}

// Start begins background upload processing.
func (m *Manager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return nil
	}
	if m.uploader == nil {
		m.mu.Unlock()
		return fmt.Errorf("uploader not configured")
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	m.running, m.cancel, m.done = true, cancel, done
	m.mu.Unlock()
	go func() {
		defer close(done)
		_ = m.ob.Run(rctx, outbox.DelivererFunc(m.deliver))
		// Reset running on every exit path (ctx cancellation too), so
		// IsRunning does not lie and Start works again.
		m.mu.Lock()
		if m.done == done {
			m.running = false
		}
		m.mu.Unlock()
	}()
	return nil
}

// Stop gracefully stops the upload process.
func (m *Manager) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	cancel, done := m.cancel, m.done
	m.running = false
	m.mu.Unlock()
	cancel()
	<-done
}

// IsRunning returns whether the manager is running.
func (m *Manager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// GetProgress returns upload progress for a report.
func (m *Manager) GetProgress(_ context.Context, reportID string) (*Progress, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r := m.reports[reportID]
	if r == nil {
		return nil, fmt.Errorf("report not found: %s", reportID)
	}
	return r.CalculateProgress(), nil
}

// GetStats returns statistics of the reports this manager knows and the
// bytes its outbox holds.
func (m *Manager) GetStats(_ context.Context) (*StorageStats, error) {
	st := m.ob.Stats()
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := &StorageStats{TotalStorageBytes: st.PendingBytes + st.DeadLetterBytes}
	for _, r := range m.reports {
		s.TotalReports++
		s.TotalChunks += r.TotalChunks
		s.CompletedChunks += r.CompletedChunks
		s.FailedChunks += r.FailedChunks
		s.PendingChunks += r.TotalChunks - r.CompletedChunks - r.FailedChunks
		switch r.Status {
		case ReportStatusPending:
			s.PendingReports++
		case ReportStatusUploading:
			s.UploadingReports++
		case ReportStatusCompleted:
			s.CompletedReports++
		case ReportStatusFailed:
			s.FailedReports++
		}
	}
	return s, nil
}

// deliver uploads one chunk (outbox.Deliverer).
func (m *Manager) deliver(ctx context.Context, d *outbox.Delivery) (any, error) {
	if d.Meta.Kind != outbox.KindChunk {
		return nil, outbox.Permanent(0, "not a chunk", nil, nil)
	}
	reportID := d.Meta.Attrs[attrReportID]
	var cd ChunkData
	if err := json.Unmarshal(d.Payload, &cd); err != nil {
		m.chunkDone(reportID, false)
		return nil, outbox.Permanent(0, "stored chunk is not valid", nil, err)
	}
	m.mu.RLock()
	up := m.uploader
	m.mu.RUnlock()
	if up == nil {
		return nil, errors.New("uploader not configured")
	}
	m.setStatus(reportID, ReportStatusUploading)
	err := up.UploadChunk(ctx, &cd)
	if delay := time.Duration(m.cfg.UploadDelayMs) * time.Millisecond; delay > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(delay):
		}
	}
	if err == nil {
		if m.isVerbose() {
			fmt.Printf("[chunk] Chunk %d/%d uploaded for report %s\n", cd.ChunkIndex+1, cd.TotalChunks, reportID)
		}
		m.chunkDone(reportID, true)
		return nil, nil
	}
	if ctx.Err() != nil {
		return nil, err
	}
	if m.isVerbose() {
		fmt.Printf("[chunk] Chunk %d failed for report %s: %v\n", cd.ChunkIndex, reportID, err)
	}
	cls := classifyUpload(err)
	var perm *outbox.PermanentError
	if !errors.As(cls, &perm) && m.cfg.MaxRetries > 0 && d.State.Attempts+1 > m.cfg.MaxRetries {
		cls = outbox.Permanent(0, fmt.Sprintf("gave up after %d attempts: %v", d.State.Attempts+1, err), nil, err)
	}
	if errors.As(cls, &perm) {
		m.chunkDone(reportID, false)
	}
	return nil, cls
}

// classifyUpload maps an upload error to the outbox classes: a rejected key
// pauses, other 4xx (except 429) are permanent, the rest are transient.
func classifyUpload(err error) error {
	if core.AuthFailureStatus(err) != 0 {
		return outbox.Unauthorized(err)
	}
	var se interface{ HTTPStatusCode() int }
	if errors.As(err, &se) {
		code := se.HTTPStatusCode()
		if code >= 400 && code < 500 && code != http.StatusTooManyRequests {
			return outbox.Permanent(code, err.Error(), nil, err)
		}
	}
	return err
}

func (m *Manager) setStatus(reportID string, s ReportStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r := m.reports[reportID]; r != nil && r.Status == ReportStatusPending {
		r.Status = s
		r.UpdatedAt = time.Now()
	}
}

// chunkDone records one finished chunk and fires the callbacks.
func (m *Manager) chunkDone(reportID string, ok bool) {
	m.mu.Lock()
	r := m.reports[reportID]
	if r == nil {
		m.mu.Unlock()
		return
	}
	if ok {
		r.CompletedChunks++
	} else {
		r.FailedChunks++
	}
	now := time.Now()
	r.UpdatedAt = now
	finished := r.CompletedChunks+r.FailedChunks >= r.TotalChunks
	if finished {
		if r.FailedChunks > 0 {
			r.Status = ReportStatusFailed
		} else {
			r.Status = ReportStatusCompleted
		}
		r.CompletedAt = &now
	}
	progress := r.CalculateProgress()
	failed := r.FailedChunks
	status := r.Status
	onProgress, onComplete, onError := m.onProgress, m.onComplete, m.onError
	verbose := m.verbose
	m.mu.Unlock()

	if onProgress != nil {
		onProgress(progress)
	}
	if !finished {
		return
	}
	if status == ReportStatusCompleted {
		if onComplete != nil {
			onComplete(reportID)
		}
		if verbose {
			fmt.Printf("[chunk] Report %s completed successfully\n", reportID)
		}
		return
	}
	if onError != nil {
		onError(reportID, fmt.Errorf("report failed: %d chunks failed", failed))
	}
	if verbose {
		fmt.Printf("[chunk] Report %s failed: %d/%d chunks failed\n", reportID, failed, progress.TotalChunks)
	}
}

// ProcessPending uploads every pending chunk that can be uploaded now and
// returns when none is left (or only chunks backing off after a failure).
func (m *Manager) ProcessPending(ctx context.Context) error {
	m.mu.RLock()
	up, running := m.uploader, m.running
	m.mu.RUnlock()
	if up == nil {
		return fmt.Errorf("uploader not configured")
	}
	m.ob.Wake()
	if running {
		return m.ob.Wait(ctx)
	}
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = m.ob.Run(rctx, outbox.DelivererFunc(m.deliver))
	}()
	err := m.ob.Wait(ctx)
	cancel()
	<-done
	return err
}

// Outbox returns the manager's outbox (for its Stats and dead letters).
func (m *Manager) Outbox() *outbox.Outbox { return m.ob }

// Close stops uploading and releases the outbox. Chunks not uploaded yet stay
// on disk for the next process.
func (m *Manager) Close() error {
	m.Stop()
	return m.ob.Close()
}

// outboxDir is where the manager keeps its chunks.
func (c *Config) outboxDir() string {
	if c.OutboxDir != "" {
		return c.OutboxDir
	}
	if c.DatabasePath != "" {
		return filepath.Join(filepath.Dir(c.DatabasePath), "chunk-outbox")
	}
	return filepath.Join(filepath.Dir(defaultDatabasePath()), "chunk-outbox")
}
