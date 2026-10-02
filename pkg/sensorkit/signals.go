package sensorkit

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

// signalKey marks a context made by SignalContext, so Run does not install a
// second handler.
type signalKey struct{}

// exitInterrupted is the exit code of a second signal (128 + SIGINT).
const exitInterrupted = 130

// SignalContext returns a context canceled by the first SIGINT or SIGTERM:
// the sensor drains (running scans get the drain grace and are then handed
// back to the platform). A second signal exits at once with code 130. Run
// does this by itself; call SignalContext when the sensor does work of its
// own before Run (tool detection), so a signal then stops it the same way.
// The messages go to out (nil: standard output). stop releases the signals.
func SignalContext(parent context.Context, out io.Writer) (ctx context.Context, stop context.CancelFunc) {
	out = orStdout(out)
	ctx, cancel := context.WithCancel(context.WithValue(parent, signalKey{}, true))
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigCh:
		case <-done:
			return
		}
		_, _ = fmt.Fprintln(out, "\nShutting down... (running scans get a grace period; signal again to stop at once)")
		cancel()
		select {
		case <-sigCh:
		case <-done:
			return
		}
		_, _ = fmt.Fprintln(out, "Stopping at once: running scans are killed and left to the platform's recovery")
		os.Exit(exitInterrupted)
	}()
	var stopped bool
	return ctx, func() {
		if stopped {
			return
		}
		stopped = true
		signal.Stop(sigCh)
		close(done)
		cancel()
	}
}
