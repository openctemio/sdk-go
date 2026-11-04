package toolhost

import (
	"context"
	"errors"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// taskCredentials are the credentials one task of m may receive: in a
// platform job, the organization's (asked once for this task, never kept)
// merged with the operator's local ones (core.MergeToolCredentials);
// otherwise the operator's. A tool that declares no credentials asks for
// nothing. When the platform cannot answer, the task runs without the
// organization's credentials and without the operator's (whether they may
// be used is the platform's answer), and line says so.
func taskCredentials(ctx context.Context, m tool.Manifest, local map[string]string) (map[string]string, *LogLine) {
	if len(m.Permissions.Credentials) == 0 {
		return local, nil
	}
	fetch := core.ToolCredentialsFrom(ctx)
	if fetch == nil {
		return local, nil
	}
	set, err := fetch(ctx, m.Name)
	switch {
	case errors.Is(err, core.ErrToolCredentialsUnsupported):
		return local, nil
	case err != nil:
		return nil, &LogLine{Level: "warn", Msg: "the organization's source keys could not be fetched; the task runs without them",
			Fields: map[string]any{"tool": m.Name, "error": err.Error()}}
	case set == nil:
		set = &core.ToolCredentialSet{}
	}
	return core.MergeToolCredentials(set, local), nil
}
