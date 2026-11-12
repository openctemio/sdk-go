package core

import (
	"fmt"
	"os"
	"testing"

	"github.com/openctemio/sdk-go/pkg/sensorkit/executor"
)

// testReadTool is the first argument that makes the test binary a tool that
// reads the file named next and prints OK or ERR (sandbox tests).
const testReadTool = "__core-test-read"

// TestMain clears the CI markers: converters file code findings on the CI
// job's repository when the caller names none, so a test run inside GitHub
// Actions or GitLab CI would otherwise see a repository a local run does not.
//
// The test binary is also the sandbox's launcher and a tool that reads a
// file (testReadTool), for tests that run tasks in the real sandbox.
func TestMain(m *testing.M) {
	executor.RunLauncherIfRequested()
	if len(os.Args) > 2 && os.Args[1] == testReadTool {
		if _, err := os.ReadFile(os.Args[2]); err != nil {
			fmt.Println("ERR", err)
			os.Exit(3)
		}
		fmt.Println("OK")
		os.Exit(0)
	}
	_ = os.Unsetenv("GITHUB_ACTIONS")
	_ = os.Unsetenv("GITLAB_CI")
	os.Exit(m.Run())
}
