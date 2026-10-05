package sensorkit

import (
	"fmt"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/executor"
	"github.com/openctemio/sdk-go/pkg/outbox"
)

// EnvSandbox sets the tool sandbox mode: off, auto (default) or required.
const EnvSandbox = "SENSOR_SANDBOX"

// setupSandbox installs the executor backend every tool run uses, with the
// kit's protected paths, and logs what it enforces.
func (k *Kit) setupSandbox() error {
	mode, ok := executor.ParseMode(strings.TrimSpace(envOr(k.opts.Sandbox, EnvSandbox)))
	if !ok {
		return usageError(fmt.Errorf("%s must be off, auto or required", EnvSandbox))
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: mode, ReadDeny: k.protectedPaths()})
	if err != nil {
		return usageError(err)
	}
	executor.SetCurrent(b)
	st := b.Status()
	switch {
	case mode == executor.ModeOff:
		_, _ = fmt.Fprintf(k.out, "  Tool sandbox: off (%s=off)\n", EnvSandbox)
	case st.Sandboxed:
		_, _ = fmt.Fprintf(k.out, "  Tool sandbox: %s; private task directory, rlimits, no_new_privs, landlock v%d, seccomp %t\n", st.Mode, st.Landlock, st.Seccomp)
	}
	for _, m := range st.Missing {
		_, _ = fmt.Fprintf(k.errw, "Warning: tool sandbox: %s\n", m)
	}
	return nil
}

// protectedPaths are the files no tool may read: the renewable API key, the
// outbox and its key, the local policy, and the sensor's own list.
func (k *Kit) protectedPaths() []string {
	var out []string
	add := func(p string) {
		if p = strings.TrimSpace(p); p != "" {
			if _, err := os.Lstat(p); err == nil {
				out = append(out, p)
			}
		}
	}
	add(k.s.key.file)
	add(k.s.outbox.Config.Dir)
	add(k.s.outbox.Config.KeyFile)
	if d := k.s.outbox.Config.Dir; d != "" {
		add(outbox.DefaultKeyFile(d))
	}
	if lp := k.s.local; lp != nil {
		add(lp.Path())
	}
	add(k.opts.LocalPolicyPath)
	for _, p := range k.opts.ProtectedPaths {
		add(p)
	}
	return out
}
