package core

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
)

// funcExecutor runs fn for every command.
type funcExecutor func(ctx context.Context, cmd *Command) (*CommandExecutionResult, error)

func (f funcExecutor) Execute(ctx context.Context, cmd *Command) (*CommandExecutionResult, error) {
	return f(ctx, cmd)
}

// outputPoller is a job poller fixture whose executor is exec.
func outputPoller(t *testing.T, required, pinned bool, exec CommandExecutor) *jobPollerFixture {
	t.Helper()
	f := newJobPollerFixture(t, required, pinned)
	f.poller = NewCommandPoller(f.client, exec, &CommandPollerConfig{MaxConcurrent: 2, AllowedTypes: []string{"scan"}})
	f.poller.SetJobGuard(f.g)
	return f
}

func runWithOutput(t *testing.T, out json.RawMessage) *CommandResult {
	t.Helper()
	f := outputPoller(t, false, false, funcExecutor(func(context.Context, *Command) (*CommandExecutionResult, error) {
		return &CommandExecutionResult{Output: out, Metadata: map[string]any{"k": "v"}}, nil
	}))
	f.offer(jsCmd, jsPayload, nil)
	f.run()
	r := f.client.results[jsCmd]
	if r == nil {
		t.Fatal("no result")
	}
	return r
}

// The typed output reaches the result as the handler wrote it: key order,
// number formats and string escapes that encoding/json would change are
// kept, and encoding the result again (the complete body, the outbox)
// leaves them.
func TestPollerKeepsTheTypedOutputAsWritten(t *testing.T) {
	out := json.RawMessage(`{"zeta":1.50,"alpha":[1e3,-0.0,10000000000000000000001],"s":"café","nested":{"b":true,"a":null}}`)
	r := runWithOutput(t, out)
	if r.Status != "completed" {
		t.Fatalf("result = %+v", r)
	}
	if !bytes.Equal(r.Output, out) {
		t.Fatalf("output = %s, want %s", r.Output, out)
	}
	if r.Metadata["k"] != "v" {
		t.Fatalf("metadata = %v", r.Metadata)
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var back struct {
		Output json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back.Output, out) {
		t.Fatalf("encoded output = %s, want %s", back.Output, out)
	}
}

// Whitespace between tokens is dropped (the compact form); the values stay.
func TestPollerCompactsTheTypedOutput(t *testing.T) {
	r := runWithOutput(t, json.RawMessage("{ \"b\" : 1.0 ,\n \"a\": \"x y\" }\n"))
	if string(r.Output) != `{"b":1.0,"a":"x y"}` {
		t.Fatalf("output = %s", r.Output)
	}
}

func TestPollerFailsAnOversizedOrInvalidOutput(t *testing.T) {
	big := json.RawMessage(`"` + strings.Repeat("x", MaxCommandOutputBytes) + `"`)
	cases := map[string]struct {
		out  json.RawMessage
		code string
	}{
		"over the limit": {big, ErrorCodeOutputTooLarge},
		"not json":       {json.RawMessage(`{"a":`), ErrorCodeOutputInvalid},
		"two values":     {json.RawMessage(`1 2`), ErrorCodeOutputInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := runWithOutput(t, tc.out)
			if r.Status != "failed" || r.ErrorCode != tc.code || r.Error == "" || r.Output != nil {
				t.Fatalf("result = status %q code %q error %q output %d bytes", r.Status, r.ErrorCode, r.Error, len(r.Output))
			}
		})
	}
	// At the limit it is kept.
	at := json.RawMessage(`"` + strings.Repeat("x", MaxCommandOutputBytes-2) + `"`)
	if r := runWithOutput(t, at); r.Status != "completed" || len(r.Output) != MaxCommandOutputBytes {
		t.Fatalf("output at the limit: status %q, %d bytes", r.Status, len(r.Output))
	}
}

// A command without typed output reports none.
func TestPollerReportsNoOutputWithoutOne(t *testing.T) {
	if r := runWithOutput(t, nil); r.Status != "completed" || r.Output != nil {
		t.Fatalf("result = %+v", r)
	}
	b, _ := json.Marshal(&CommandResult{Status: "completed"})
	if strings.Contains(string(b), `"output"`) {
		t.Fatalf("a result without output encodes one: %s", b)
	}
}

// The handler can tell whether its command's signed job was verified.
func TestJobVerifiedFromContext(t *testing.T) {
	var mu sync.Mutex
	var seen []bool
	exec := funcExecutor(func(ctx context.Context, _ *Command) (*CommandExecutionResult, error) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, JobVerifiedFromContext(ctx))
		return &CommandExecutionResult{}, nil
	})
	check := func(name string, f *jobPollerFixture, env func(f *jobPollerFixture) json.RawMessage, want bool) {
		t.Helper()
		seen = nil
		f.offer(jsCmd, jsPayload, env(f))
		f.run()
		if len(seen) != 1 || seen[0] != want {
			t.Fatalf("%s: verified seen %v, want [%v] (result %+v)", name, seen, want, f.client.results[jsCmd])
		}
	}
	signed := func(f *jobPollerFixture) json.RawMessage { return f.signer.sign(t, jsCmd, 2, jsPayload, nil) }
	unsigned := func(*jobPollerFixture) json.RawMessage { return nil }

	check("verified signed job", outputPoller(t, true, true, exec), signed, true)
	check("unsigned job, key pinned, not required", outputPoller(t, false, true, exec), unsigned, false)
	check("no key pinned", outputPoller(t, false, false, exec), unsigned, false)

	check("signed job, no key pinned", outputPoller(t, false, false, exec), signed, false)

	if JobVerifiedFromContext(context.Background()) {
		t.Fatal("a context the poller did not set says verified")
	}
}
