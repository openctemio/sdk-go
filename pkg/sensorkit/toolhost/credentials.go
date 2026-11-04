package toolhost

import (
	"context"
	"errors"
	"strings"

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

// minRedactedPart is the shortest colon-separated part of a credential that
// is redacted on its own.
const minRedactedPart = 8

// redactionValues are what the task's output is scrubbed of for one
// credential: the whole value (at least 4 characters), and each part of a
// pair ("TOKEN:ORG_ID", "EMAIL:KEY", "HOST:KEY") of at least 8 characters,
// since a tool that splits the value may print a part alone.
func redactionValues(v string) []string {
	var out []string
	if len(v) >= 4 {
		out = append(out, v)
	}
	if strings.Contains(v, ":") {
		for _, part := range strings.Split(v, ":") {
			if len(part) >= minRedactedPart && part != v {
				out = append(out, part)
			}
		}
	}
	return out
}
