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

// EnvSandboxNetwork sets network confinement of those commands: auto
// (default), required or off (see executor.Config.ConfineNetwork).
const EnvSandboxNetwork = "OPENCTEM_SANDBOX_NETWORK"

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
	nm, ok := executor.ParseMode(strings.TrimSpace(os.Getenv(EnvSandboxNetwork)))
	if !ok {
		return fmt.Errorf("%s=%q: use off, auto or required", EnvSandboxNetwork, os.Getenv(EnvSandboxNetwork))
	}
	b, err := executor.NewProcessBackend(executor.Config{Mode: m,
		ConfineNetwork: nm != executor.ModeOff && m != executor.ModeOff, RequireNetwork: nm == executor.ModeRequired})
	if err != nil {
		return err
	}
	executor.SetCurrent(b)
	st := b.Status()
	for _, miss := range st.Missing {
		_, _ = fmt.Fprintf(w, "note: sandbox: %s\n", miss)
	}
	if st.NetworkMissing != "" {
		_, _ = fmt.Fprintf(w, "note: network not confined: %s\n", st.NetworkMissing)
	}
	return nil
}
