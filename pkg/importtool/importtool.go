// Package importtool is the file importer as a parser-class tool of the tool
// contract (pkg/tool): it converts files other security tools export (Nessus
// v2 XML, Qualys detection XML with its KnowledgeBase, DefectDojo Generic
// Findings JSON, CycloneDX, SPDX, osv-scanner results, CSAF and OpenVEX)
// into CTIS with the ctis importer package, so the conversion runs in the
// tool sandbox of a sensor instead of on the platform.
//
// Stability: Beta (docs/STABILITY.md).
//
// The tool reads only the task's inputs, which the runtime places in the
// task's private directory; it has no network and no other filesystem
// access (manifest: class parser, network none, workdir only). Each input is
// hostile: it must be a regular file inside the task directory (no
// absolute path, no "..", no link), within the size limit, and it is parsed
// with the importer's limits (no XML entities or external resources, depth,
// size and record caps).
//
// A VEX document (CSAF, OpenVEX, a CycloneDX VEX) holds statements about
// products, not records of the task; they are written to the artifact
// vex-statements.json for the platform to apply, never emitted as findings.
package importtool

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/ctis/importer"

	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Name is the tool's name.
const Name = "file-import"

// MaxInputBytes is the largest input file the tool reads.
const MaxInputBytes = 256 << 20

// VEXArtifact is the artifact the statements of VEX documents are written
// to.
const VEXArtifact = "vex-statements.json"

// Config is the tool's configuration.
type Config struct {
	// Format of every input; auto detects it per input from its first
	// bytes.
	Format string `json:"format" default:"auto" enum:"auto,nessus,qualys,defectdojo,cyclonedx,spdx,osv,csaf,openvex" description:"Format of the inputs; auto detects it per input."`
	// MinSeverity drops findings below it.
	MinSeverity string `json:"min_severity" default:"info" enum:"info,low,medium,high,critical" description:"Findings below this severity are left out."`
}

// Manifest describes the tool.
var Manifest = tool.Manifest{
	Name:        Name,
	Version:     "1.0.0",
	Description: "Converts exported scanner, SBOM, VEX and findings files to CTIS (Nessus, Qualys with KnowledgeBase, DefectDojo Generic JSON, CycloneDX, SPDX, osv-scanner, CSAF, OpenVEX).",
	Class:       tool.Parser,
	Tier:        tool.T0,
	Consumes:    []string{"file:application/xml", "file:application/json", "file:application/zip"},
	Produces: []string{
		"asset:host", "asset:ip_address", "asset:domain", "asset:repository", "asset:container",
		"asset:unclassified", "finding:vulnerability", "finding:compliance", "dependency",
	},
	Permissions: tool.Permissions{Network: tool.NetNone, Filesystem: tool.FSWorkdir},
	Resources: tool.Resources{
		Timeout:        tool.Duration(30 * time.Minute),
		MaxOutputBytes: 256 << 20,
		MaxRecords:     1_000_000,
	},
}

// New returns the tool.
func New() tool.Tool { return tool.New(Manifest, run) }

func run(ctx tool.Context, task tool.Task, cfg Config) error {
	if len(task.Inputs) == 0 {
		return tool.Invalid("file-import: the task has no input file")
	}
	inputs := make([]resolved, 0, len(task.Inputs))
	for _, in := range task.Inputs {
		r, err := resolve(ctx.Workdir(), in)
		if err != nil {
			return err
		}
		inputs = append(inputs, r)
	}
	forced := importer.Format(cfg.Format)
	if forced == "auto" {
		forced = ""
	}
	if err := detect(inputs, forced); err != nil {
		return err
	}
	var statements []importer.VEXStatement
	for i := range inputs {
		in := &inputs[i]
		if in.format == importer.FormatQualysKB {
			continue // read with its detection file
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		res, err := parseOne(ctx, in, inputs, cfg)
		if err != nil {
			return err
		}
		logIssues(ctx, in.input.Name, res)
		statements = append(statements, res.VEX...)
		if len(res.Report.Findings) > 0 || len(res.Report.Assets) > 0 || len(res.Report.Dependencies) > 0 {
			if err := ctx.Emit().Report(res.Report); err != nil {
				return err
			}
		}
	}
	if len(statements) > 0 {
		if err := writeStatements(ctx, statements); err != nil {
			return err
		}
	}
	return nil
}

type resolved struct {
	input  tool.Input
	path   string
	format importer.Format
}

// resolve checks an input names a regular file inside the task directory.
func resolve(workdir string, in tool.Input) (resolved, error) {
	p := in.Path
	if p == "" || !filepath.IsLocal(p) {
		return resolved{}, tool.Invalid("file-import: input %q is not a path inside the task directory", in.Name)
	}
	full := filepath.Join(workdir, p)
	// Every element must be a directory or the file itself, never a link:
	// a link could point outside the task directory.
	cur := workdir
	for _, el := range strings.Split(filepath.ToSlash(filepath.Clean(p)), "/") {
		cur = filepath.Join(cur, el)
		fi, err := os.Lstat(cur)
		if err != nil {
			return resolved{}, tool.Invalid("file-import: input %q: %v", in.Name, errors.Unwrap(err))
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return resolved{}, tool.Invalid("file-import: input %q is a link", in.Name)
		}
	}
	fi, err := os.Lstat(full)
	if err != nil || !fi.Mode().IsRegular() {
		return resolved{}, tool.Invalid("file-import: input %q is not a regular file", in.Name)
	}
	if fi.Size() > MaxInputBytes {
		return resolved{}, tool.Invalid("file-import: input %q is larger than %d bytes", in.Name, MaxInputBytes)
	}
	return resolved{input: in, path: full}, nil
}

// detect names the format of each input.
func detect(inputs []resolved, forced importer.Format) error {
	for i := range inputs {
		f, err := os.Open(inputs[i].path)
		if err != nil {
			return tool.Failed(err)
		}
		head := make([]byte, importer.SniffLen)
		n, _ := io.ReadFull(f, head)
		_ = f.Close()
		head = head[:n]
		if importer.IsZip(head) {
			return tool.Invalid("file-import: input %q is an archive; the runtime extracts archives before the task", inputs[i].input.Name)
		}
		got, ok := importer.Detect(head)
		switch {
		case ok && got == importer.FormatQualysKB:
			inputs[i].format = got
		case forced != "":
			inputs[i].format = forced
		case ok:
			inputs[i].format = got
		default:
			return tool.Invalid("file-import: the format of input %q is not recognized", inputs[i].input.Name)
		}
	}
	return nil
}

func parseOne(ctx tool.Context, in *resolved, all []resolved, cfg Config) (*importer.Result, error) {
	f, err := os.Open(in.path)
	if err != nil {
		return nil, tool.Failed(err)
	}
	defer func() { _ = f.Close() }()
	opts := importer.Options{
		Format:      in.format,
		Limits:      importer.Limits{MaxInputBytes: MaxInputBytes},
		SourceType:  "scanner",
		MinSeverity: ctis.Severity(cfg.MinSeverity),
	}
	if in.format == importer.FormatQualys {
		for i := range all {
			if all[i].format == importer.FormatQualysKB {
				kb, err := os.Open(all[i].path)
				if err != nil {
					return nil, tool.Failed(err)
				}
				defer func() { _ = kb.Close() }()
				opts.QualysKnowledgeBase = kb
				break
			}
		}
	}
	res, err := importer.Parse(ctx, f, opts)
	if err != nil {
		var pe *importer.ParseError
		if errors.As(err, &pe) {
			if errors.Is(err, ctx.Err()) && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, tool.Invalid("file-import: input %q: %s", in.input.Name, pe.Error())
		}
		return nil, tool.Failed(err)
	}
	return res, nil
}

// logIssues logs the problems of an input with their lines (at most 20),
// and the source fields the mapping spec does not know.
func logIssues(ctx tool.Context, name string, res *importer.Result) {
	ctx.Log().Info("input imported", "input", name, "format", string(res.Format),
		"records", res.Stats.Records, "findings", res.Stats.Findings, "assets", res.Stats.Assets,
		"components", res.Stats.Components, "statements", res.Stats.Statements, "skipped", res.Stats.Skipped,
		"issues", len(res.Issues), "unmapped_fields", len(res.Unmapped))
	for i, is := range res.Issues {
		if i == 20 {
			ctx.Log().Warn("more problems not logged", "input", name, "count", len(res.Issues)-20)
			break
		}
		ctx.Log().Warn("input problem", "input", name, "line", is.Line, "path", is.Path, "message", is.Message)
	}
	if len(res.Unmapped) > 0 {
		ctx.Log().Info("source fields without a mapping", "input", name, "fields", strings.Join(res.Unmapped, ", "))
	}
}

func writeStatements(ctx tool.Context, statements []importer.VEXStatement) error {
	w, err := ctx.Artifact(VEXArtifact, "application/json")
	if err != nil {
		return tool.Failed(fmt.Errorf("vex artifact: %w", err))
	}
	enc := json.NewEncoder(w)
	if err := enc.Encode(map[string]any{"statements": statements}); err != nil {
		_ = w.Close()
		return tool.Failed(fmt.Errorf("vex artifact: %w", err))
	}
	return w.Close()
}
