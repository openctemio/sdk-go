package importtool

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// BundleLimits bound a results directory (the ctis defaults).
var BundleLimits = importer.DefaultBundleLimits()

// runBundle imports the one input, a directory of the task, as a bundle.
func runBundle(ctx tool.Context, task tool.Task, cfg Config) error {
	if len(task.Inputs) != 1 {
		return tool.Invalid("file-import: a reconftw import takes exactly one input, the results directory")
	}
	in := task.Inputs[0]
	files, err := bundleFiles(ctx.Workdir(), in)
	if err != nil {
		return err
	}
	if _, ok := importer.DetectBundle(bundleNames(files)); !ok {
		return tool.Invalid("file-import: input %q is not a reconFTW results directory", in.Name)
	}
	res, err := importer.ParseBundle(ctx, files, importer.Options{
		Limits:      importer.Limits{MaxInputBytes: MaxInputBytes},
		Bundle:      BundleLimits,
		SourceType:  "scanner",
		MinSeverity: ctis.Severity(cfg.MinSeverity),
	})
	if err != nil {
		var pe *importer.ParseError
		if errors.As(err, &pe) {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return tool.Invalid("file-import: input %q: %s", in.Name, pe.Error())
		}
		return tool.Failed(err)
	}
	logIssues(ctx, in.Name, res)
	for _, sp := range res.Skipped {
		ctx.Log().Info("file skipped on purpose", "input", in.Name, "path", sp.Path, "reason", sp.Reason)
	}
	// The runtime checks each record alone, so an endpoint cannot name an
	// asset of the report by reference; the platform resolves its origin by
	// value (the origin asset is in the report).
	for i := range res.Report.Endpoints {
		res.Report.Endpoints[i].OriginRef = ""
	}
	if len(res.Report.Assets) > 0 || len(res.Report.Findings) > 0 || len(res.Report.Endpoints) > 0 {
		return ctx.Emit().Report(res.Report)
	}
	return nil
}

func bundleNames(files []importer.ArchiveFile) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Name
	}
	return out
}

// bundleFiles lists the regular files under the input directory. Every
// element must be a directory or a regular file: a link (it could point
// outside the task directory) or a special file refuses the bundle, like
// the archive guards of the ctis importer.
func bundleFiles(workdir string, in tool.Input) ([]importer.ArchiveFile, error) {
	p := in.Path
	if p == "" || !filepath.IsLocal(p) {
		return nil, tool.Invalid("file-import: input %q is not a path inside the task directory", in.Name)
	}
	root := filepath.Join(workdir, p)
	cur := workdir
	for _, el := range strings.Split(filepath.ToSlash(filepath.Clean(p)), "/") {
		cur = filepath.Join(cur, el)
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil, tool.Invalid("file-import: input %q: %v", in.Name, errors.Unwrap(err))
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, tool.Invalid("file-import: input %q is a link", in.Name)
		}
	}
	if fi, err := os.Lstat(root); err != nil || !fi.IsDir() {
		return nil, tool.Invalid("file-import: input %q is not a directory", in.Name)
	}
	var files []importer.ArchiveFile
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || !(d.IsDir() || d.Type().IsRegular()) {
			return tool.Invalid("file-import: input %q holds a link or a special file", in.Name)
		}
		if d.IsDir() {
			return nil
		}
		if len(files) >= BundleLimits.MaxFilesListed {
			return tool.Invalid("file-import: input %q holds more than %d files", in.Name, BundleLimits.MaxFilesListed)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		full := path
		files = append(files, importer.NewArchiveFile(filepath.ToSlash(rel), info.Size(), func() (io.ReadCloser, error) {
			return os.Open(full)
		}))
		return nil
	})
	if err != nil {
		var te *tool.Error
		if errors.As(err, &te) {
			return nil, err
		}
		return nil, tool.Failed(err)
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}
