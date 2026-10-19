package core

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// eventLog records the order of what happens to a command.
type eventLog struct {
	mu   sync.Mutex
	ev   []string
	done chan struct{}
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	l.ev = append(l.ev, e)
	l.mu.Unlock()
}

func (l *eventLog) events() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.ev...)
}

type journalClient struct {
	countingCommandClient
	log *eventLog
}

func (c *journalClient) StartCommand(context.Context, string) error {
	c.log.add("platform-start")
	return nil
}

func (c *journalClient) ReportCommandResult(context.Context, string, *CommandResult) error {
	c.log.add("result")
	return nil
}

type journalExecutor struct{ log *eventLog }

func (e *journalExecutor) Execute(context.Context, *Command) (*CommandExecutionResult, error) {
	e.log.add("execute")
	return &CommandExecutionResult{}, nil
}

type fakeJournal struct {
	log      *eventLog
	startErr error
}

func (j *fakeJournal) JobStarted(cmdID, tenant string, epoch int) error {
	j.log.add("journal-start:" + cmdID)
	return j.startErr
}

func (j *fakeJournal) JobFinished(cmdID, tenant string) error {
	j.log.add("journal-finish:" + cmdID)
	close(j.log.done)
	return nil
}

func runJournaled(t *testing.T, j *fakeJournal) []string {
	t.Helper()
	log := j.log
	cc := &journalClient{countingCommandClient: countingCommandClient{cmds: make(chan *Command, 1)}, log: log}
	p := NewCommandPoller(cc, &journalExecutor{log: log}, &CommandPollerConfig{PollInterval: 10 * time.Millisecond})
	p.SetJobJournal(j)
	cc.cmds <- &Command{ID: "c1", Type: "scan"}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = p.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case <-log.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("the job was never closed in the journal: %v", log.events())
	}
	return log.events()
}

// The journal knows a job from the platform's start until its result is
// queued: a crash anywhere in between leaves a record the next start
// reports.
func TestCommandPoller_JournalsEveryJob(t *testing.T) {
	got := runJournaled(t, &fakeJournal{log: &eventLog{done: make(chan struct{})}})
	want := []string{"platform-start", "journal-start:c1", "execute", "result", "journal-finish:c1"}
	if len(got) != len(want) {
		t.Fatalf("events %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

// A journal that cannot write does not stop the job.
func TestCommandPoller_JournalFailureStillRuns(t *testing.T) {
	got := runJournaled(t, &fakeJournal{log: &eventLog{done: make(chan struct{})}, startErr: errors.New("disk")})
	ran := false
	for _, e := range got {
		ran = ran || e == "execute"
	}
	if !ran {
		t.Fatalf("job did not run: %v", got)
	}
}
