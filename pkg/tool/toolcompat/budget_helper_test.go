package toolcompat

import "github.com/openctemio/sdk-go/pkg/adapt"

// testBudget is the per-host budget the package's tests run a tool under
// (the tool host refuses a tool that connects to its targets without one).
func testBudget() *adapt.HostBudget {
	b := adapt.DefaultBudget()
	return &b
}
