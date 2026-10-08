package toolcli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// EnvSandbox sets the sandbox mode of "openctem tool run" and "test" when
// --sandbox is not given: off, auto (default) or required.
const EnvSandbox = "OPENCTEM_SANDBOX"

// InstallSandbox runs every task of this process in the same process
// sandbox a sensor uses (pkg/sensorkit/executor), so a tool that works here
// works on a sensor: a private task directory, rlimits, no_new_privs,
// Landlock and seccomp. mode "" reads OPENCTEM_SANDBOX, then defaults to
// auto, which enforces what this host supports and notes the rest on w;
// required refuses to run without every control. The program must call
// executor.RunLauncherIfRequested first thing in main.
func InstallSandbox(mode string, w io.Writer) error {
	if mode == "" {
		mode = os.Getenv(EnvSandbox)
	}
	m, ok := executor.ParseMode(strings.TrimSpace(mode))
	if !ok {
		return fmt.Errorf("sandbox mode %q: use off, auto or required", mode)
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: m})
	if err != nil {
		return err
	}
	executor.SetCurrent(b)
	for _, miss := range b.Status().Missing {
		_, _ = fmt.Fprintf(w, "note: sandbox: %s\n", miss)
	}
	return nil
}
