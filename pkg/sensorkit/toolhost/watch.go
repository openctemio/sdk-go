package toolhost

import (
	"fmt"
	"time"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// The run watch (core.RunWatch): two bounds on a running tool besides its
// idle timeout (which heartbeats satisfy) and its task timeout.
//
//   - Finished: the tool settled every target of the task but sent no
//     result within FinishGrace. It is stopped (a protocol cancel, then a
//     kill after the grace) and the run ends as the targets say: every
//     target's records are delivered, with a warning line saying the
//     sensor stopped the tool.
//   - Inactive: the tool sent nothing but heartbeats and its processes used
//     less than inactiveCPU of CPU for Inactivity. It is stopped as timed
//     out: what it settled is delivered (partial), the rest is unfinished.
//     Where process CPU time cannot be read this check is off: a tool is
//     never stopped for silence alone.

// Watch stop reasons (session.watchStop).
const (
	watchFinished = "finished"
	watchInactive = "inactive"
)

// inactiveCPU is the least CPU a tool's processes use over the inactivity
// window to count as working.
const inactiveCPU = time.Second

// watchFor is the run's watch: the caller's fields, else the job's, then
// the defaults.
func watchFor(o, job core.RunWatch) core.RunWatch {
	if o.FinishGrace == 0 {
		o.FinishGrace = job.FinishGrace
	}
	if o.Inactivity == 0 {
		o.Inactivity = job.Inactivity
	}
	return o.Effective()
}

// watchInterval is how often the watch is checked (0: never).
func (s *session) watchInterval() time.Duration {
	d := s.watch.FinishGrace
	if s.watch.Inactivity > 0 && (d == 0 || s.watch.Inactivity < d) {
		d = s.watch.Inactivity
	}
	if d <= 0 {
		return 0
	}
	return min(max(d/10, 50*time.Millisecond), 30*time.Second)
}

// watchdog reports why the tool should be stopped now ("": it should not).
func (s *session) watchdog(now time.Time) string {
	if g := s.watch.FinishGrace; g > 0 && len(s.p.task.Targets) > 0 && !s.p.task.IsRetest() {
		if s.settledAt.IsZero() && len(s.p.asm.Unfinished()) == 0 {
			s.settledAt = now
		}
		if !s.settledAt.IsZero() && now.Sub(s.settledAt) >= g {
			return watchFinished
		}
	}
	if win := s.watch.Inactivity; win > 0 && s.cpu != nil {
		cpu, ok := s.cpu.Read()
		if !ok {
			return ""
		}
		if cpu-s.cpuMark >= inactiveCPU {
			s.cpuMark, s.cpuMarkAt = cpu, now
		}
		last := s.lastActive
		if s.cpuMarkAt.After(last) {
			last = s.cpuMarkAt
		}
		if now.Sub(last) >= win {
			return watchInactive
		}
	}
	return ""
}

// watchOutcome is the run's error after the watch stopped the tool (nil:
// every target was settled, the run is as complete as its targets say),
// and it logs what happened to the task's command log.
func (s *session) watchOutcome() *tool.Error {
	switch s.watchStop {
	case watchFinished:
		s.log("warn", fmt.Sprintf("the tool settled every target but did not finish within %s; the sensor stopped it and delivered every target's results", s.watch.FinishGrace),
			map[string]any{"watchdog": watchFinished, "finish_grace": s.watch.FinishGrace.String()})
		return nil
	default:
		detail := fmt.Sprintf("the tool sent no output and used no CPU for %s; the sensor stopped it", s.watch.Inactivity)
		s.log("warn", detail, map[string]any{"watchdog": watchInactive, "inactivity": s.watch.Inactivity.String()})
		return &tool.Error{Class: tool.Timeout, Retryable: true, Detail: detail}
	}
}
