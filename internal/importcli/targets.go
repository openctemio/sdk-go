package importcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/openctemio/sdk-go/pkg/useragent"
)

// The input side of a tool a person runs: "openctem targets export" lists
// the organization's in-scope assets of one kind for the tool, and
// "openctem run" exports them, runs the person's command on them and
// imports what it wrote.

// TargetKinds maps a target kind to the platform's asset types.
var TargetKinds = map[string][]string{
	"domain":  {"domain", "subdomain"},
	"ip":      {"ip_address"},
	"url":     {"website", "http_service", "web_application", "api"},
	"service": {"service", "open_port"},
}

// Export limits.
const (
	exportPerPage  = 100
	MaxExportPages = 1000 // 100 000 targets
)

const targetsUsage = `usage: openctem targets export --type domain|ip|url|service [flags]

Prints the organization's assets of one kind, one per line (or JSON lines),
for a tool you run yourself. By default only assets an active scope entry
covers (scope status in_scope); the API key's data scope applies.

flags:
`

type exportOptions struct {
	kind, scope, format string
	tags                []string
}

// TargetsMain runs "openctem targets <args>".
func TargetsMain(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 || args[0] != "export" {
		_, _ = fmt.Fprint(stderr, targetsUsage)
		return ExitUsage
	}
	fs := flag.NewFlagSet("targets export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, targetsUsage); fs.PrintDefaults() }
	var o exportOptions
	var base, caFile string
	bindExportFlags(fs, &o)
	fs.StringVar(&base, "url", "", "the console URL (default $"+EnvURL+")")
	fs.StringVar(&caFile, "ca-file", "", "a PEM file of CA certificates to trust in addition to the system's (default $"+EnvCAFile+")")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintln(stderr, "openctem targets export: unexpected arguments")
		return ExitUsage
	}
	c, err := clientFromEnv(base, caFile, getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem targets export: %v\n", err)
		return ExitUsage
	}
	n, err := exportTargets(context.Background(), c, o, stdout)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem targets export: %s\n", clean(err.Error(), 400))
		return ExitFail
	}
	_, _ = fmt.Fprintf(stderr, "%d %s targets\n", n, o.kind)
	return ExitOK
}

type tagList []string

func (t *tagList) String() string { return strings.Join(*t, ",") }
func (t *tagList) Set(v string) error {
	*t = append(*t, strings.TrimSpace(v))
	return nil
}

func bindExportFlags(fs *flag.FlagSet, o *exportOptions) {
	fs.StringVar(&o.kind, "type", "", "what to export: domain, ip, url or service")
	fs.StringVar(&o.scope, "scope", "in_scope", "scope status: in_scope (an active entry covers it), not_covered, internal, or all")
	fs.StringVar(&o.format, "export-format", "lines", "lines (one value per line) or json (one {\"type\",\"value\"} object per line)")
	fs.Var((*tagList)(&o.tags), "tag", "only assets with this tag (repeatable)")
}

func clientFromEnv(base, caFile string, getenv func(string) string) (*client, error) {
	if strings.TrimSpace(base) == "" {
		base = getenv(EnvURL)
	}
	return newClient(strings.TrimSpace(base), getenv(EnvAPIKey), firstNonEmpty(caFile, getenv(EnvCAFile)))
}

// exportTargets writes the assets page by page and returns how many.
func exportTargets(ctx context.Context, c *client, o exportOptions, w io.Writer) (int, error) {
	types, ok := TargetKinds[o.kind]
	if !ok {
		return 0, errors.New("--type must be domain, ip, url or service")
	}
	if o.format != "lines" && o.format != "json" {
		return 0, errors.New("--export-format must be lines or json")
	}
	q := url.Values{"types": {strings.Join(types, ",")}, "per_page": {fmt.Sprint(exportPerPage)}, "sort": {"name"}}
	switch o.scope {
	case "all":
	case "in_scope", "not_covered", "internal":
		q.Set("scope_status", o.scope)
	default:
		return 0, errors.New("--scope must be in_scope, not_covered, internal or all")
	}
	if len(o.tags) > 0 {
		q.Set("tags", strings.Join(o.tags, ","))
	}
	seen := map[string]bool{}
	n := 0
	for page := 1; page <= MaxExportPages; page++ {
		q.Set("page", fmt.Sprint(page))
		var resp struct {
			Data []struct {
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"data"`
			TotalPages int `json:"total_pages"`
		}
		if err := c.getJSON(ctx, "/api/v1/assets", q, &resp); err != nil {
			return n, err
		}
		for _, a := range resp.Data {
			v := clean(strings.TrimSpace(a.Name), 2048)
			if v == "" || strings.ContainsAny(v, " \t") || seen[v] {
				continue
			}
			seen[v] = true
			var line string
			if o.format == "json" {
				b, _ := json.Marshal(struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				}{clean(a.Type, 64), v})
				line = string(b)
			} else {
				line = v
			}
			if _, err := fmt.Fprintln(w, line); err != nil {
				return n, err
			}
			n++
		}
		if page >= resp.TotalPages || len(resp.Data) == 0 {
			return n, nil
		}
	}
	return n, fmt.Errorf("more than %d targets: narrow the export with --tag", MaxExportPages*exportPerPage)
}

func (c *client) getJSON(ctx context.Context, path string, q url.Values, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path, q), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "openctem-import/"+useragent.SDKVersion())
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, firstNonEmpty(e.Message, http.StatusText(resp.StatusCode)))
	}
	return json.Unmarshal(data, v)
}

const runUsage = `usage: openctem run --type domain|ip|url|service --format <f> [flags] -- <command> [args]

Exports the in-scope targets of one kind to a private file, runs your command
with {targets_file} (and {output_file}) replaced in its arguments, and
imports what it wrote ({output_file}, else its standard output). No shell is
used, and the command does not see OPENCTEM_API_KEY.

  openctem run --type domain --format lines --as domain --tool puredns -- puredns resolve {targets_file} -w {output_file}
  openctem run --type ip --format nmap -- nmap -sV -iL {targets_file} -oX {output_file}

flags:
`

// RunMain runs "openctem run <args>".
func RunMain(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	dash := -1
	for i, a := range args {
		if a == "--" {
			dash = i
			break
		}
	}
	if dash < 0 || dash == len(args)-1 {
		_, _ = fmt.Fprint(stderr, runUsage)
		return ExitUsage
	}
	ownArgs, command := args[:dash], args[dash+1:]
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprint(stderr, runUsage); fs.PrintDefaults() }
	var o exportOptions
	bindExportFlags(fs, &o)
	var timeout time.Duration
	fs.DurationVar(&timeout, "timeout", 4*time.Hour, "stop the command after this long")
	// The import flags pass through to openctem import.
	importFlags := []string{"format", "as", "tool", "mapping", "min-severity", "url", "ca-file"}
	vals := map[string]*string{}
	for _, f := range importFlags {
		vals[f] = fs.String(f, "", "as for openctem import")
	}
	var dryRun bool
	var wait time.Duration
	fs.BoolVar(&dryRun, "dry-run", false, "as for openctem import (the command still runs)")
	fs.DurationVar(&wait, "wait", 60*time.Second, "as for openctem import")
	if err := fs.Parse(ownArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	c, err := clientFromEnv(*vals["url"], *vals["ca-file"], getenv)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem run: %v\n", err)
		return ExitUsage
	}
	dir, err := os.MkdirTemp("", "openctem-run-")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem run: %v\n", err)
		return ExitFail
	}
	defer func() { _ = os.RemoveAll(dir) }()
	targetsFile, outputFile := filepath.Join(dir, "targets.txt"), filepath.Join(dir, "output")
	var tb bytes.Buffer
	ctx := context.Background()
	n, err := exportTargets(ctx, c, o, &tb)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem run: %s\n", clean(err.Error(), 400))
		return ExitFail
	}
	if n == 0 {
		_, _ = fmt.Fprintf(stderr, "openctem run: no %s targets in scope: nothing to run\n", o.kind)
		return ExitFail
	}
	if err := writeFile(targetsFile, tb.Bytes()); err != nil {
		_, _ = fmt.Fprintf(stderr, "openctem run: %v\n", err)
		return ExitFail
	}
	_, _ = fmt.Fprintf(stderr, "%d %s targets in %s\n", n, o.kind, targetsFile)

	usesOutput := false
	argv := make([]string, len(command))
	for i, a := range command {
		usesOutput = usesOutput || strings.Contains(a, "{output_file}")
		a = strings.ReplaceAll(a, "{targets_file}", targetsFile)
		argv[i] = strings.ReplaceAll(a, "{output_file}", outputFile)
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(rctx, argv[0], argv[1:]...) // #nosec G204 -- the person's own command, no shell
	cmd.Env = childEnv(os.Environ())
	cmd.Stderr = stderr
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, left: MaxInputBytes}
	if err := cmd.Run(); err != nil {
		// A scanner may exit non-zero after writing results (findings
		// found): import what it wrote, and say so.
		_, _ = fmt.Fprintf(stderr, "openctem run: the command ended with: %v\n", err)
	}
	output := out.Bytes()
	if usesOutput {
		data, err := readFileLimited(outputFile, MaxInputBytes)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "openctem run: read {output_file}: %v\n", err)
			return ExitFail
		}
		output = data
	}
	iargs := []string{"--wait", wait.String()}
	for _, f := range importFlags {
		if v := *vals[f]; v != "" {
			iargs = append(iargs, "--"+f, v)
		}
	}
	if dryRun {
		iargs = append(iargs, "--dry-run")
	}
	return Main(iargs, bytes.NewReader(output), stdout, stderr, getenv)
}

// childEnv is the environment of the person's command: everything but the
// API key.
func childEnv(env []string) []string {
	out := env[:0:0]
	for _, kv := range env {
		// Windows names are case-blind: Openctem_Api_Key is the same variable.
		if name, _, ok := strings.Cut(kv, "="); ok && strings.EqualFold(name, EnvAPIKey) {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// limitedWriter keeps at most left bytes and drops the rest.
type limitedWriter struct {
	w    io.Writer
	left int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	if len(p) > 0 {
		if _, err := l.w.Write(p); err != nil {
			return 0, err
		}
		l.left -= int64(len(p))
	}
	return n, nil
}
