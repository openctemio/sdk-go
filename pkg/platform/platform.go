// Package platform provides components for running agents in platform mode.
//
// Platform agents are centrally managed by OpenCTEM and execute jobs on behalf
// of tenants. Unlike tenant agents that run within a tenant's infrastructure,
// platform agents are deployed and operated by the OpenCTEM platform itself.
//
// Key components:
//   - LeaseManager: Handles K8s-style lease renewal for health monitoring
//   - Bootstrapper: Handles agent registration using bootstrap tokens
//   - JobPoller: Long-polls for jobs using /platform/poll endpoint
//   - Client: Extended client with platform-specific endpoints
//
// Usage:
//
//	// Bootstrap a new platform agent
//	bootstrapper := platform.NewBootstrapper(baseURL, bootstrapToken)
//	creds, err := bootstrapper.Register(ctx, &platform.RegistrationRequest{
//	    Name: "scanner-001",
//	    Capabilities: []string{"sast", "sca"},
//	})
//
//	// Create platform client
//	client := platform.NewClient(&platform.ClientConfig{
//	    BaseURL: baseURL,
//	    APIKey:  creds.APIKey,
//	    AgentID: creds.AgentID,
//	})
//
//	// Start lease manager
//	leaseManager := platform.NewLeaseManager(client, &platform.LeaseConfig{
//	    LeaseDuration: 60 * time.Second,
//	    RenewInterval: 20 * time.Second,
//	})
//	go leaseManager.Start(ctx)
//
//	// Start job poller
//	poller := platform.NewJobPoller(client, executor, &platform.PollerConfig{
//	    MaxJobs:     5,
//	    PollTimeout: 30 * time.Second,
//	})
//	poller.Start(ctx)
package platform

import (
	"time"
)

// Version is the platform package version.
const Version = "1.0.0"

// Default configuration values.
const (
	DefaultLeaseDuration     = 60 * time.Second
	DefaultRenewInterval     = 20 * time.Second
	DefaultPollTimeout       = 30 * time.Second
	DefaultMaxConcurrentJobs = 5
	DefaultBootstrapTimeout  = 30 * time.Second
)

// AgentCredentials contains the credentials returned after agent registration.
type AgentCredentials struct {
	AgentID   string `json:"agent_id"`
	APIKey    string `json:"api_key"`
	APIPrefix string `json:"api_prefix"`
}

// AgentInfo contains information about a registered platform agent.
type AgentInfo struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Capabilities []string  `json:"capabilities"`
	Region       string    `json:"region"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// LeaseInfo contains information about the current lease.
type LeaseInfo struct {
	AgentID          string    `json:"agent_id"`
	HolderIdentity   string    `json:"holder_identity"`
	LeaseDurationSec int       `json:"lease_duration_seconds"`
	AcquireTime      time.Time `json:"acquire_time"`
	RenewTime        time.Time `json:"renew_time"`
	ResourceVersion  int       `json:"resource_version"`
}

// JobInfo contains information about a platform job.
type JobInfo struct {
	ID         string                 `json:"id"`
	Type       string                 `json:"type"`
	Priority   int                    `json:"priority"`
	TenantID   string                 `json:"tenant_id"`
	Payload    map[string]interface{} `json:"payload"`
	AuthToken  string                 `json:"auth_token"` // JWT for tenant data access
	CreatedAt  time.Time              `json:"created_at"`
	TimeoutSec int                    `json:"timeout_seconds"`

	// WorkflowContext is set when the job was triggered by a workflow.
	// It allows correlating job execution with workflow runs.
	WorkflowContext *WorkflowContext `json:"workflow_context,omitempty"`
}

// WorkflowContext contains context information when a job is triggered
// by the Workflow Executor as part of an automation workflow.
type WorkflowContext struct {
	// WorkflowID is the UUID of the workflow definition.
	WorkflowID string `json:"workflow_id"`

	// WorkflowRunID is the UUID of the specific workflow execution.
	WorkflowRunID string `json:"workflow_run_id"`

	// TriggerType indicates what triggered the workflow (e.g., "finding_created", "schedule", "manual").
	TriggerType string `json:"trigger_type"`

	// ActionNodeID is the UUID of the action node that triggered this job.
	ActionNodeID string `json:"action_node_id"`

	// ActionNodeKey is the node_key of the action node (e.g., "run_scan_1").
	ActionNodeKey string `json:"action_node_key"`
}

// JobResult contains the result of a completed job.
type JobResult struct {
	JobID         string                 `json:"job_id"`
	Status        string                 `json:"status"` // completed, failed, canceled
	CompletedAt   time.Time              `json:"completed_at"`
	DurationMs    int64                  `json:"duration_ms"`
	FindingsCount int                    `json:"findings_count"`
	Error         string                 `json:"error,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`

	// WorkflowContext is echoed back if the job was triggered by a workflow.
	// This allows the Workflow Executor to correlate results with workflow runs.
	WorkflowContext *WorkflowContext `json:"workflow_context,omitempty"`
}

// HasWorkflowContext returns true if the job was triggered by a workflow.
func (j *JobInfo) HasWorkflowContext() bool {
	return j.WorkflowContext != nil && j.WorkflowContext.WorkflowRunID != ""
}

// HasWorkflowContext returns true if the result includes workflow context.
func (r *JobResult) HasWorkflowContext() bool {
	return r.WorkflowContext != nil && r.WorkflowContext.WorkflowRunID != ""
}

// SystemMetrics contains agent system metrics for health reporting.
type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskPercent   float64 `json:"disk_percent"`
	CurrentJobs   int     `json:"current_jobs"`
	MaxJobs       int     `json:"max_jobs"`
}
