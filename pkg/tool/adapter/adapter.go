// Package adapter runs a tool (pkg/tool) as an adapter process: the tool's
// side of adapter protocol v1, newline-delimited JSON on stdin and stdout,
// one task per process (docs/rfcs/sensor-sdk-v2.md, D.4.2).
//
// Stability: Stable (docs/STABILITY.md).
//
// A Go tool shipped as its own binary calls Serve in main. A sensor that
// compiles tools in calls Dispatch first thing in main (after the sandbox
// launcher): the runtime runs each task by re-executing the sensor as
// "<sensor> __openctem-tool <name>" inside the task sandbox, so a Go tool
// gets the same isolation as a tool in any other language and never runs
// in the sensor's process.
//
// While it serves, the process's standard output is the protocol channel
// only: anything the tool's code prints with fmt.Print goes to standard
// error instead (captured, redacted and capped by the runtime).
package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openctemio/sdk-go/internal/toolrt"
	"github.com/openctemio/sdk-go/internal/toolwire"
	"github.com/openctemio/sdk-go/pkg/sdk"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// ToolArg is the first argument that makes a sensor binary serve one of
// its compiled-in tools ("<sensor> __openctem-tool <name>"). It is not a
// user-facing command.
const ToolArg = "__openctem-tool"

// DescribeArg makes Serve print the tool's manifest as JSON and exit
// (openctem manifest export reads it).
const DescribeArg = "--describe"

// Exit codes.
const (
	exitOK       = 0
	exitProtocol = 3
	exitUsage    = 2
)

// heartbeatEvery keeps a quiet tool alive under the runtime's idle timeout.
var heartbeatEvery = 30 * time.Second

// Dispatch serves a compiled-in tool when this process was started as
// "<program> __openctem-tool <name>", and never returns then. Otherwise it
// returns at once. Call it first thing in main, after
// executor.RunLauncherIfRequested.
func Dispatch(tools ...tool.Tool) {
	if len(os.Args) < 2 || os.Args[1] != ToolArg {
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: <program> "+ToolArg+" <tool>")
		os.Exit(exitUsage)
	}
	for _, t := range tools {
		if t.Manifest().Name == os.Args[2] {
			os.Exit(serveProcess(t))
		}
	}
	fmt.Fprintf(os.Stderr, "openctem tool: no compiled-in tool %q\n", os.Args[2])
	os.Exit(exitUsage)
}

// Serve runs t as an adapter on this process's stdin and stdout and exits.
// With the single argument --describe it prints t's manifest and exits.
func Serve(t tool.Tool) {
	if len(os.Args) == 2 && os.Args[1] == DescribeArg {
		b, err := json.MarshalIndent(t.Manifest().Normalized(), "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(exitUsage)
		}
		_, _ = os.Stdout.Write(append(b, '\n'))
		os.Exit(exitOK)
	}
	os.Exit(serveProcess(t))
}

// serveProcess serves t on the process's stdio: it keeps stdout for the
// protocol (moving fd 1 to stderr), makes the process non-dumpable and
// treats SIGTERM as a cancel.
func serveProcess(t tool.Tool) int {
	out, err := protectStdout()
	if err != nil {
		fmt.Fprintf(os.Stderr, "openctem tool: %v\n", err)
		return exitProtocol
	}
	makeUndumpable()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	if err := ServeIO(ctx, t, os.Stdin, out); err != nil {
		fmt.Fprintf(os.Stderr, "openctem tool: %v\n", err)
		return exitProtocol
	}
	return exitOK
}

// ServeIO runs the tool side of the protocol on in and out: the handshake,
// then describe and validate requests, then one run. It returns after the
// run's result (or when in ends), never running a second task.
func ServeIO(ctx context.Context, t tool.Tool, in io.Reader, out io.Writer) error {
	m := t.Manifest().Normalized()
	if err := m.Validate(); err != nil {
		return err
	}
	r := toolwire.NewReader(in)
	w := toolwire.NewWriter(out)

	line, err := r.Next()
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	var hello toolwire.Hello
	if err := toolwire.Decode(line, &hello); err != nil || hello.Type != toolwire.TypeHello {
		return fmt.Errorf("handshake: the first message must be hello")
	}
	if !supports(hello.Protocol, toolwire.Version) || !supports(rangeOf(m.Protocol), toolwire.Version) {
		return fmt.Errorf("handshake: no common protocol version (runtime %v, tool %d)", hello.Protocol, toolwire.Version)
	}
	if err := w.Write(toolwire.HelloReply{Envelope: toolwire.Env(toolwire.TypeHello), Protocol: toolwire.Version,
		SDK: toolwire.SDKInfo{Name: "openctem-sdk-go", Version: sdk.Version}, Features: toolwire.Features}); err != nil {
		return err
	}
	for {
		line, err := r.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		env, err := toolwire.Peek(line)
		if err != nil {
			continue // not a message: ignored
		}
		switch env.Type {
		case toolwire.TypeDescribe:
			b, err := json.Marshal(m)
			if err != nil {
				return err
			}
			if err := w.Write(toolwire.ManifestMsg{Envelope: toolwire.Env(toolwire.TypeManifest), Manifest: b}); err != nil {
				return err
			}
		case toolwire.TypeValidate:
			var v toolwire.Validate
			if err := toolwire.Decode(line, &v); err != nil {
				return fmt.Errorf("validate: %w", err)
			}
			if err := w.Write(validate(ctx, t, m, v.Task)); err != nil {
				return err
			}
		case toolwire.TypeRun:
			var run toolwire.Run
			if err := toolwire.Decode(line, &run); err != nil {
				return fmt.Errorf("run: %w", err)
			}
			return runTask(ctx, t, m, run.Task, r, w)
		default:
			// Unknown types are ignored (a newer runtime).
		}
	}
}

func rangeOf(p tool.Range) []int {
	maxV := p.Max
	if maxV == 0 {
		maxV = toolwire.Version
	}
	var out []int
	for v := max(p.Min, 1); v <= maxV; v++ {
		out = append(out, v)
	}
	return out
}

func supports(vs []int, v int) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}

func validate(ctx context.Context, t tool.Tool, m tool.Manifest, task tool.Task) toolwire.Validation {
	res := toolwire.Validation{Envelope: toolwire.Env(toolwire.TypeValidation), OK: true}
	fail := func(path, msg string) {
		res.OK = false
		res.Errors = append(res.Errors, toolwire.ValidationError{Path: path, Message: toolrt.CleanString(msg)})
	}
	schema, err := m.ConfigSchema()
	switch {
	case err != nil:
		fail("/config", err.Error())
	case schema != nil:
		raw := bytes.TrimSpace(task.Config)
		if len(raw) == 0 {
			raw = []byte("{}")
		}
		if err := schema.ValidateJSON(raw); err != nil {
			fail("/config", err.Error())
		}
	case len(bytes.TrimSpace(task.Config)) > 0 && string(bytes.TrimSpace(task.Config)) != "{}" && string(bytes.TrimSpace(task.Config)) != "null":
		fail("/config", "the tool takes no configuration")
	}
	if ierr := toolrt.CheckRetest(m, task); ierr != nil {
		fail("/retest", ierr.Detail)
	}
	if v, ok := t.(tool.Validator); ok && res.OK {
		if err := v.Validate(ctx, task); err != nil {
			fail("", tool.CapDetail(err.Error()))
		}
	}
	return res
}

// runTask runs the one task: the tool in a goroutine, cancel messages and
// the end of stdin watched, heartbeats while it runs, then the result.
func runTask(ctx context.Context, t tool.Tool, m tool.Manifest, rt toolwire.RunTask, r *toolwire.Reader, w *toolwire.Writer) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !rt.Deadline.IsZero() {
		var c context.CancelFunc
		ctx, c = context.WithDeadline(ctx, rt.Deadline)
		defer c()
	}
	secrets := map[string]tool.Secret{}
	for _, c := range rt.Credentials {
		secrets[c.Name] = tool.NewSecret(c.Value)
	}
	rt.Credentials = nil
	s := newSink(w, rt.Workdir)
	tctx := toolrt.NewContext(ctx, toolrt.ContextConfig{Manifest: m, Task: rt.Task, Sink: s, Secrets: secrets, Workdir: rt.Workdir})

	// The runtime's later messages: cancel, or the end of stdin (the
	// runtime is gone) both stop the tool.
	go func() {
		for {
			line, err := r.Next()
			if err != nil {
				cancel()
				return
			}
			if env, err := toolwire.Peek(line); err == nil && env.Type == toolwire.TypeCancel {
				cancel()
				return
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		tk := time.NewTicker(heartbeatEvery)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				_ = w.Write(toolwire.Envelope{V: toolwire.Version, Type: toolwire.TypeHeartbeat})
			}
		}
	}()
	runErr := safeRun(t, tctx, rt.Task)
	close(done)
	status := tool.StatusOK
	switch {
	case runErr != nil && runErr.Class == tool.Canceled:
		status = tool.StatusCanceled
	case runErr != nil:
		status = tool.StatusFailed
	case s.refused():
		status = tool.StatusPartial
	}
	if runErr != nil {
		runErr.Detail = tool.CapDetail(toolrt.CleanString(runErr.Detail))
	}
	return w.Write(toolwire.Result{Envelope: toolwire.Env(toolwire.TypeResult), Status: status,
		Error: toolwire.FromError(runErr), Stats: toolwire.Stats{Records: s.count()}})
}

// safeRun turns a panic into a tool error (the runtime sees the result
// instead of a crash, with the panic in stderr).
func safeRun(t tool.Tool, ctx tool.Context, task tool.Task) (err *tool.Error) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "openctem tool: panic: %v\n", r)
			err = &tool.Error{Class: tool.ToolError, Detail: fmt.Sprintf("panic: %v", r)}
		}
	}()
	if ierr := toolrt.CheckRetest(t.Manifest().Normalized(), task); ierr != nil {
		return ierr
	}
	return tool.AsError(toolrt.Invoke(t, ctx, task))
}
