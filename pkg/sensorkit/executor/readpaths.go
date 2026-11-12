package executor

import (
	"context"
	"slices"
)

type readPathsKey struct{}

// WithReadPaths returns ctx carrying paths a job's tasks may read beneath a
// private root (see TaskSpec.ReadPaths): a job's own files kept under the
// task root, like the custom templates the platform signed for it. Every
// task started for the job with this context gets them; a task of another
// job (on a shared sensor, another organization's) does not, and cannot
// read or list them. Paths already carried are kept.
func WithReadPaths(ctx context.Context, paths ...string) context.Context {
	if len(paths) == 0 {
		return ctx
	}
	all := slices.Clone(ReadPathsFrom(ctx))
	for _, p := range paths {
		if p != "" && !slices.Contains(all, p) {
			all = append(all, p)
		}
	}
	return context.WithValue(ctx, readPathsKey{}, all)
}

// ReadPathsFrom returns the read paths ctx carries (WithReadPaths), for a
// caller to add to its TaskSpec.ReadPaths. The slice is a copy.
func ReadPathsFrom(ctx context.Context) []string {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(readPathsKey{}).([]string)
	return slices.Clone(p)
}

// NewJobDir makes a private directory (0700) under TaskRoot for a job's own
// files that its tools read (a rewritten or signed copy of its custom
// templates or rules) and returns ctx granting it (WithReadPaths) with the
// directory. The sandbox hides it from every other task. The caller removes
// the directory when the job is done. Never put such files in the system's
// temporary directory: a task launched later, of any job, can read them.
func NewJobDir(ctx context.Context, prefix string) (context.Context, string, error) {
	dir, err := NewTaskDir(prefix)
	if err != nil {
		return ctx, "", err
	}
	return WithReadPaths(ctx, dir), dir, nil
}
