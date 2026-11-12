package core

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

const (
	bigCommandID   = "0b7f7a1e-5a3c-4f43-9d0e-2f6c1c8f3a11"
	smallCommandID = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
)

// tooLargeAnswer is what the client returns for an answer over 10 MiB.
type tooLargeAnswer struct{ head []byte }

func (e *tooLargeAnswer) Error() string        { return "response body exceeds 10485760 bytes" }
func (e *tooLargeAnswer) Unwrap() error        { return ErrResponseTooLarge }
func (e *tooLargeAnswer) ResponseHead() []byte { return e.head }

// oversizeClient is a platform that holds a command too big for one answer
// next to a small one: any answer that includes the big command is too large.
type oversizeClient struct {
	mu     sync.Mutex
	queue  []string // command ids, in the platform's order
	asks   []int
	failed map[string]string
	acked  []string
	head   func(first string) []byte
}

func newOversizeClient() *oversizeClient {
	return &oversizeClient{
		queue:  []string{bigCommandID, smallCommandID},
		failed: map[string]string{},
		head: func(first string) []byte {
			return []byte(`{"commands":[{"id":"` + first + `","type":"scan","payload":"aaaaaaaa`)
		},
	}
}

func (c *oversizeClient) GetCommands(ctx context.Context) (*GetCommandsResponse, error) {
	return c.GetCommandsLimit(ctx, 10)
}

func (c *oversizeClient) GetCommandsLimit(_ context.Context, limit int) (*GetCommandsResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.asks = append(c.asks, limit)
	n := min(limit, len(c.queue))
	out := &GetCommandsResponse{}
	for _, id := range c.queue[:n] {
		if id == bigCommandID {
			return nil, &tooLargeAnswer{head: c.head(c.queue[0])}
		}
		out.Commands = append(out.Commands, &Command{ID: id, Type: "scan"})
	}
	return out, nil
}

func (c *oversizeClient) AcknowledgeCommand(_ context.Context, id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.acked = append(c.acked, id)
	return nil
}
func (c *oversizeClient) StartCommand(context.Context, string) error { return nil }
func (c *oversizeClient) ReportCommandProgress(context.Context, string, int, string) error {
	return nil
}

func (c *oversizeClient) ReportCommandResult(_ context.Context, id string, r *CommandResult) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r.Status == "failed" {
		c.failed[id] = r.Error
	}
	for i, q := range c.queue {
		if q == id {
			c.queue = append(c.queue[:i], c.queue[i+1:]...)
			break
		}
	}
	return nil
}

func (c *oversizeClient) askList() []int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]int(nil), c.asks...)
}

type idExecutor struct {
	mu  sync.Mutex
	ran []string
}

func (e *idExecutor) Execute(_ context.Context, cmd *Command) (*CommandExecutionResult, error) {
	e.mu.Lock()
	e.ran = append(e.ran, cmd.ID)
	e.mu.Unlock()
	return &CommandExecutionResult{}, nil
}

func (e *idExecutor) ids() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.ran...)
}

// captureStdout runs f and returns what it printed.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

// One command whose payload pushes the poll answer over the limit must not
// stop intake: the poller logs it (not verbose), asks for fewer commands,
// and at one command fails the oversized one by its id, then runs the next.
func TestCommandPoller_OversizedAnswerFailsTheCommandAndResumes(t *testing.T) {
	c := newOversizeClient()
	e := &idExecutor{}
	p := NewCommandPoller(c, e, &CommandPollerConfig{MaxConcurrent: 4})
	ctx := context.Background()

	out := captureStdout(t, func() {
		for range 5 {
			p.pollAndExecute(ctx)
			p.activeCmds.Wait()
		}
	})

	if got := fmt.Sprint(c.askList()); !strings.HasPrefix(got, "[4 2 1 ") {
		t.Fatalf("asks = %s, want to start 4 2 1 (halving)", got)
	}
	if !strings.Contains(out, "larger than 10 MiB") {
		t.Fatalf("no log line about the oversized answer in a non-verbose poller; output:\n%s", out)
	}
	c.mu.Lock()
	reason, failed := c.failed[bigCommandID]
	c.mu.Unlock()
	if !failed || !strings.Contains(reason, "larger than the 10 MiB") {
		t.Fatalf("oversized command not failed with a clear reason (failed=%v, reason=%q)", failed, reason)
	}
	if got := e.ids(); len(got) != 1 || got[0] != smallCommandID {
		t.Fatalf("executed %v, want only the small command", got)
	}
	// Nothing was ever executed from the truncated answer.
	for _, id := range e.ids() {
		if id == bigCommandID {
			t.Fatal("the oversized command was executed")
		}
	}
	// Once the culprit is gone the poller asks for its full size again.
	asks := c.askList()
	if last := asks[len(asks)-1]; last != 4 {
		t.Fatalf("asks = %v, want the last one back at 4", asks)
	}
}

// The same oversized state is logged once, not on every poll.
func TestCommandPoller_OversizedLogIsThrottled(t *testing.T) {
	c := newOversizeClient()
	c.head = func(string) []byte { return []byte(`{"commands":[`) } // no id to read
	p := NewCommandPoller(c, &idExecutor{}, &CommandPollerConfig{MaxConcurrent: 1})
	out := captureStdout(t, func() {
		for range 6 {
			p.pollAndExecute(context.Background())
		}
	})
	if n := strings.Count(out, "larger than 10 MiB"); n != 1 {
		t.Fatalf("logged %d times in 6 polls, want 1; output:\n%s", n, out)
	}
	if p.ownGate.unreachable {
		t.Fatal("an oversized answer counted as a connection failure")
	}
	if len(c.failed) != 0 {
		t.Fatalf("failed %v with no readable id", c.failed)
	}
}

func TestFirstCommandID(t *testing.T) {
	const id = smallCommandID
	for _, tc := range []struct {
		name string
		head string
		want string
	}{
		{"first key", `{"commands":[{"id":"` + id + `","type":"scan","payload":"xx`, id},
		{"id after other keys", `{"commands":[{"type":"scan","priority":"high","tags":["a","b"],"id":"` + id + `","payload":"x`, id},
		{"other top-level key first", `{"next":{"a":1},"commands":[{"id":"` + id + `"`, id},
		{"cut inside the id", `{"commands":[{"id":"7c1d2e3f-4a5b-4c6d`, ""},
		{"cut before the id", `{"commands":[{"type":"sc`, ""},
		{"not a uuid", `{"commands":[{"id":"../../etc/passwd","type":"scan"`, ""},
		{"id not a string", `{"commands":[{"id":{"x":1},"type":"scan"`, ""},
		{"no commands key", `{"items":[{"id":"` + id + `"}]}`, ""},
		{"commands not a list", `{"commands":{"id":"` + id + `"}}`, ""},
		{"empty", ``, ""},
		{"html", `<html>too big</html>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := firstCommandID([]byte(tc.head))
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("firstCommandID = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}
