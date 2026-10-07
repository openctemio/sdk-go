package toolrt

import "github.com/openctemio/sdk-go/pkg/tool"

// CheckWebScope refuses a task whose web scope is invalid, or that a
// networked tool cannot keep to: one that does not declare
// features.web_scope would run unrestricted. It returns nil for a task
// without a web scope.
func CheckWebScope(m tool.Manifest, task tool.Task) *tool.Error {
	if task.WebScope == nil {
		return nil
	}
	if err := task.WebScope.Validate(); err != nil {
		return &tool.Error{Class: tool.RefusedByPolicy, Detail: err.Error()}
	}
	if m.Normalized().Permissions.Network != tool.NetNone && (m.Features == nil || !m.Features.WebScope) {
		return &tool.Error{Class: tool.RefusedByPolicy,
			Detail: m.Name + " does not declare features.web_scope; the job has a web scope"}
	}
	return nil
}
