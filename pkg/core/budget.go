package core

// Task budgets (api research note 122, "run liveness, not deadlines"): the
// platform sends each scan command how long one target and the whole task
// are expected to take. A target that exceeds its budget is that target's
// timeout only (the tool moves on); a task is stopped only when it overruns
// its budget by OverrunFactor. Every value is clamped here, so a platform
// (or a payload) cannot make a job run without bound or a target budget
// absurdly small.

import "time"

// Budget bounds. A target budget outside [MinTargetBudget, MaxTargetBudget]
// and a task budget outside [MinTaskBudget, MaxScanTimeout] are clamped.
const (
	MinTargetBudget = time.Second
	MaxTargetBudget = time.Hour
	MinTaskBudget   = time.Minute
	// OverrunFactor is how far past its budget a task may run before the
	// sensor stops it: a slow but progressing task is not cut at its
	// estimate.
	OverrunFactor = 2
)

// TaskBudget is a scan command's budgets (ScanCommandPayload.Budget).
type TaskBudget struct {
	// TargetSeconds is the per-target budget: a tool wrapper passes it as
	// the tool's per-request or per-host timeout (ScanOptions.TargetTimeout)
	// and RunPerTarget enforces it per target.
	TargetSeconds int `json:"target_seconds,omitempty"`
	// TaskSeconds is the expected time of the whole task.
	TaskSeconds int `json:"task_seconds,omitempty"`
	// StallSeconds is how long the task may go without finishing a target
	// before the platform considers it stalled (informational here: the
	// platform enforces it from the heartbeat's progress).
	StallSeconds int `json:"stall_seconds,omitempty"`
}

// Target is the per-target budget, clamped; 0 when none was sent.
func (b *TaskBudget) Target() time.Duration {
	if b == nil || b.TargetSeconds <= 0 {
		return 0
	}
	return clampDuration(time.Duration(b.TargetSeconds)*time.Second, MinTargetBudget, MaxTargetBudget)
}

// Overrun is how long the task may run before the sensor stops it:
// OverrunFactor times its budget, clamped to [MinTaskBudget,
// MaxScanTimeout]; 0 when no task budget was sent.
func (b *TaskBudget) Overrun() time.Duration {
	if b == nil || b.TaskSeconds <= 0 {
		return 0
	}
	return clampDuration(time.Duration(b.TaskSeconds)*time.Second*OverrunFactor, MinTaskBudget, MaxScanTimeout)
}

func clampDuration(d, lo, hi time.Duration) time.Duration {
	return max(lo, min(hi, d))
}

// jobTimeout is the job's context timeout before the local policy cap: the
// command's explicit timeout_seconds when set (never above MaxScanTimeout),
// else the task budget's overrun, else 0 (none).
func jobTimeout(timeoutSeconds int, budget *TaskBudget) time.Duration {
	if timeoutSeconds > 0 {
		return time.Duration(min(int64(timeoutSeconds), int64(MaxScanTimeout/time.Second))) * time.Second
	}
	return budget.Overrun()
}
