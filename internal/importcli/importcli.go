// Package importcli is the "openctem import" command: it converts the output
// of a tool a person ran (nmap XML, testssl.sh JSON, a list of names or URLs,
// any format of the ctis importer, or any JSON/CSV/XML through a declarative
// mapping file) into a CTIS report on this machine, and uploads that report
// to the organization with an API key, or prints or saves it instead.
//
//	nmap -sV -oX - 192.0.2.0/24 | openctem import --format nmap --dry-run
//	gau example.com | openctem import --format lines --as url
//	openctem import --format testssl --out scan.ctis.json scan.json
//	openctem import scan.ctis.json
//
// What is uploaded is exactly what --dry-run prints: the CTIS report
// (format=ctis on POST /api/v1/findings/imports). The platform validates it
// again, imports it as a partial upload with the API key's rights, judges
// every host against the organization's scope and answers with a receipt.
//
// The API key is read from OPENCTEM_API_KEY only (never a flag, so it never
// lands in shell history or a process list). It is sent only over HTTPS,
// or plain HTTP to a loopback address, and never to a redirect target.
//
// Exit status: 0 imported (or printed or saved), 1 the platform refused or
// failed the upload or the input held nothing usable, 2 a usage or input
// error, 3 the upload is still queued when --wait ends.
package importcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/importer/mapping"

	// The standard formats are adapter modules: importing one registers it
	// with the importer.
	_ "github.com/openctemio/ctis/v2/interop/csaf"
	_ "github.com/openctemio/ctis/v2/interop/cyclonedx"
	_ "github.com/openctemio/ctis/v2/interop/openvex"
	_ "github.com/openctemio/ctis/v2/interop/sarif"
	_ "github.com/openctemio/ctis/v2/interop/spdx"
)

// Exit codes.
const (
	ExitOK      = 0
	ExitFail    = 1
	ExitUsage   = 2
	ExitPending = 3
)

// Environment.
const (
	EnvURL    = "OPENCTEM_URL"
	EnvAPIKey = "OPENCTEM_API_KEY"
)

// Limits of one command.
const (
	// MaxInputs is the most files one upload carries (the import route's
	// limit).
	MaxInputs = 10
	// MaxInputBytes bounds each input read from a file or the standard
	// input.
	MaxInputBytes = 100 << 20
	// MaxUploadBytes bounds the CTIS reports of one upload together (the
	// import route accepts 110 MiB of multipart body).
	MaxUploadBytes = 100 << 20
)

const usage = `usage: openctem import [flags] [file ...]

Converts the output of a tool you ran into CTIS and imports it into your
OpenCTEM organization. No file, or "-", reads the standard input.

  nmap -sV -oX - 192.0.2.0/24 | openctem import --format nmap
  gau example.com | openctem import --format lines --as url --tool gau
  openctem import --format testssl --dry-run scan.json
  openctem import --format testssl --out scan.ctis.json scan.json
  openctem import scan.ctis.json

Environment: OPENCTEM_URL (https://console.example.com) and OPENCTEM_API_KEY
(an API key with Update Findings, Manage Assets and Import Assets).

flags:
`

type options struct {
	format, as, tool, mapping, target, minSeverity, out, url string
	dryRun, jsonOut                                          bool
	wait                                                     time.Duration
}

// env is what the command reads from its surroundings.
type env struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	getenv func(string) string
	now    func() time.Time
	open   func(string) (io.ReadCloser, error)
	send   func(ctx context.Context, c *client, files []upload) (*importResponse, error)
}

// Main runs "openctem import <args>".
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer, getenv func(string) string) int {
	return run(args, env{
		stdin: stdin, stdout: stdout, stderr: stderr, getenv: getenv, now: time.Now,
		open: func(p string) (io.ReadCloser, error) { return os.Open(p) }, // #nosec G304 -- the user names the file
		send: func(ctx context.Context, c *client, files []upload) (*importResponse, error) {
			return c.upload(ctx, files)
		},
	})
}

func run(args []string, e env) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	fs.Usage = func() {
		_, _ = fmt.Fprint(e.stderr, usage)
		fs.PrintDefaults()
	}
	var o options
	fs.StringVar(&o.format, "format", "auto", "input format: auto (detected from the content), a format name ("+strings.Join(formatNames(), ", ")+")")
	fs.StringVar(&o.as, "as", "", "--format lines only: what each line names: "+strings.Join(importer.LinesAsValues(), ", ")+" (default auto)")
	fs.StringVar(&o.tool, "tool", "", "the tool name to record (for example gau for --format lines)")
	fs.StringVar(&o.mapping, "mapping", "", "a declarative mapping file (openctem.io/mapping/v2 JSON) to read the input with instead of a format")
	fs.StringVar(&o.target, "target-hint", "", "type:value of the asset for records that name none (for example domain_name:example.com)")
	fs.StringVar(&o.minSeverity, "min-severity", "", "leave out findings below this severity (info, low, medium, high, critical)")
	fs.BoolVar(&o.dryRun, "dry-run", false, "print the CTIS report to the standard output and a summary to the standard error; send nothing")
	fs.StringVar(&o.out, "out", "", "write the CTIS report to this file and send nothing (upload it later with: openctem import <file>)")
	fs.DurationVar(&o.wait, "wait", 60*time.Second, "how long to follow the receipt until the platform applied the upload (0: do not wait)")
	fs.BoolVar(&o.jsonOut, "json", false, "print the platform's answer as JSON")
	fs.StringVar(&o.url, "url", "", "the console URL (default $"+EnvURL+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}
	usageErr := func(format string, a ...any) int {
		_, _ = fmt.Fprintf(e.stderr, "openctem import: "+format+"\n", a...)
		return ExitUsage
	}
	inputs := fs.Args()
	if len(inputs) == 0 {
		inputs = []string{"-"}
	}
	switch {
	case len(inputs) > MaxInputs:
		return usageErr("%d inputs; at most %d per upload", len(inputs), MaxInputs)
	case o.out != "" && o.dryRun:
		return usageErr("--out and --dry-run: choose one")
	case o.out != "" && len(inputs) != 1:
		return usageErr("--out writes one report: give one input")
	case o.mapping != "" && o.format != "auto":
		return usageErr("--mapping reads the input itself: leave out --format")
	case o.as != "" && o.format != string(importer.FormatLines):
		return usageErr("--as applies to --format lines only")
	}
	stdinUsed := 0
	for _, in := range inputs {
		if in == "-" {
			stdinUsed++
		}
	}
	if stdinUsed > 1 {
		return usageErr("the standard input can be read once")
	}
	conv, err := newConverter(o, e.now)
	if err != nil {
		return usageErr("%v", err)
	}

	ctx := context.Background()
	var files []upload
	total := 0
	for _, in := range inputs {
		c, err := convertInput(ctx, conv, in, e)
		if err != nil {
			_, _ = fmt.Fprintf(e.stderr, "openctem import: %s: %s\n", displayName(in), clean(err.Error(), 400))
			return ExitUsage
		}
		printSummary(e.stderr, c)
		if c.empty {
			_, _ = fmt.Fprintf(e.stderr, "openctem import: %s: nothing to import\n", displayName(in))
			return ExitFail
		}
		total += len(c.body)
		if total > MaxUploadBytes {
			return usageErr("the reports are larger than %d MiB together: split the input", MaxUploadBytes>>20)
		}
		files = append(files, upload{name: c.name, body: c.body})
	}

	switch {
	case o.dryRun:
		for _, f := range files {
			if _, err := e.stdout.Write(f.body); err != nil {
				return ExitFail
			}
		}
		return ExitOK
	case o.out != "":
		if err := writeFile(o.out, files[0].body); err != nil {
			_, _ = fmt.Fprintf(e.stderr, "openctem import: %v\n", err)
			return ExitFail
		}
		_, _ = fmt.Fprintf(e.stderr, "wrote %s (upload it with: openctem import %s)\n", o.out, o.out)
		return ExitOK
	}

	base := strings.TrimSpace(o.url)
	if base == "" {
		base = strings.TrimSpace(e.getenv(EnvURL))
	}
	c, err := newClient(base, e.getenv(EnvAPIKey))
	if err != nil {
		return usageErr("%v", err)
	}
	c.minSeverity = o.minSeverity
	resp, err := e.send(ctx, c, files)
	if err != nil {
		_, _ = fmt.Fprintf(e.stderr, "openctem import: %s\n", clean(err.Error(), 400))
		return ExitFail
	}
	if o.wait > 0 && resp.ReceiptID != "" && !resp.done() {
		resp = c.follow(ctx, resp, o.wait)
	}
	if o.jsonOut {
		enc := json.NewEncoder(e.stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	}
	printReceipt(e.stderr, resp)
	return resp.exitCode()
}

// formatNames lists the formats --format takes.
func formatNames() []string {
	var out []string
	for _, f := range importer.AllFormats() {
		if f == importer.FormatReconFTW {
			continue // a directory: upload it as a ZIP in the console
		}
		out = append(out, string(f))
	}
	return out
}

// converter turns one input into a CTIS report.
type converter struct {
	o            options
	now          func() time.Time
	format       importer.Format
	mapping      *mapping.Mapping
	defaultAsset *ctis.Asset
	minSeverity  ctis.Severity
}

func newConverter(o options, now func() time.Time) (*converter, error) {
	c := &converter{o: o, now: now}
	if f := strings.ToLower(strings.TrimSpace(o.format)); f != "" && f != "auto" {
		c.format = importer.Format(f)
		if c.format == importer.FormatReconFTW {
			return nil, errors.New("a reconFTW directory is a bundle: upload it as a ZIP on the Import results page")
		}
		if !importer.Registered(c.format) {
			return nil, fmt.Errorf("unknown --format %q; one of: auto, %s", clean(f, 32), strings.Join(formatNames(), ", "))
		}
	}
	if o.as != "" {
		ok := false
		for _, v := range importer.LinesAsValues() {
			ok = ok || v == o.as
		}
		if !ok {
			return nil, fmt.Errorf("--as must be one of %s", strings.Join(importer.LinesAsValues(), ", "))
		}
	}
	if s := strings.ToLower(strings.TrimSpace(o.minSeverity)); s != "" {
		c.minSeverity = ctis.Severity(s)
		if !c.minSeverity.IsValid() {
			return nil, errors.New("--min-severity must be one of info, low, medium, high, critical")
		}
	}
	if t := strings.TrimSpace(o.target); t != "" {
		typ, value, ok := strings.Cut(t, ":")
		at := ctis.AssetType(strings.ToLower(strings.TrimSpace(typ)))
		if !ok || !at.IsValid() {
			return nil, errors.New("--target-hint must be type:value with a CTIS asset type (domain_name:example.com, ip_address:192.0.2.1, web_origin:https://app.example.com, ...)")
		}
		v, err := ctis.CanonicalAssetValue(at, value)
		if err != nil {
			return nil, fmt.Errorf("--target-hint: %v", err)
		}
		c.defaultAsset = &ctis.Asset{Type: at, Value: v, Name: v}
	}
	if o.mapping != "" {
		data, err := readFileLimited(o.mapping, mapping.MaxMappingBytes)
		if err != nil {
			return nil, fmt.Errorf("--mapping: %v", err)
		}
		m, err := mapping.Load(data)
		if err != nil {
			return nil, fmt.Errorf("--mapping: %v", err)
		}
		c.mapping = m
	}
	return c, nil
}

// converted is one input's report.
type converted struct {
	name    string
	format  string
	tool    string
	stats   importer.Stats
	issues  []string
	vex     int
	empty   bool
	body    []byte
	unknown int
}

func convertInput(ctx context.Context, conv *converter, in string, e env) (*converted, error) {
	var r io.Reader
	name := "stdin"
	if in == "-" {
		r = e.stdin
	} else {
		f, err := e.open(in)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		r, name = f, baseName(in)
	}
	r = &limitedReader{r: r, left: MaxInputBytes}
	return conv.convert(ctx, name, r)
}

func (conv *converter) convert(ctx context.Context, name string, r io.Reader) (*converted, error) {
	out := &converted{name: name}
	src := r
	if conv.mapping != nil {
		tool := &ctis.Tool{Name: firstNonEmpty(conv.o.tool, "mapped")}
		rep, st, err := conv.mapping.Apply(ctx, r, mapping.Options{Now: conv.now, Tool: tool, DefaultAsset: conv.defaultAsset, MaxInputBytes: MaxInputBytes})
		if err != nil {
			return nil, err
		}
		for _, is := range st.Issues {
			out.issues = append(out.issues, is.String())
		}
		raw, err := json.Marshal(rep)
		if err != nil {
			return nil, err
		}
		// The mapped report goes through the CTIS reader like any other
		// CTIS file: strict decoding, record checks, scope verdicts.
		src = bytes.NewReader(raw)
	}
	opts := importer.Options{
		Format:       conv.format,
		LinesAs:      conv.o.as,
		ToolName:     conv.o.tool,
		MinSeverity:  conv.minSeverity,
		DefaultAsset: conv.defaultAsset,
		Now:          conv.now().UTC(),
		Limits:       importer.Limits{MaxInputBytes: MaxInputBytes},
	}
	if conv.mapping != nil {
		opts.Format, opts.ToolName = importer.FormatCTIS, ""
	}
	res, err := importer.Parse(ctx, src, opts)
	if err != nil {
		return nil, err
	}
	out.format, out.stats, out.vex = string(res.Format), res.Stats, len(res.VEX)
	if conv.mapping != nil {
		out.format = "mapping"
	}
	if res.Report.Tool != nil {
		out.tool = strings.TrimSpace(res.Report.Tool.Name + " " + res.Report.Tool.Version)
	}
	for _, is := range res.Issues {
		out.issues = append(out.issues, is.String())
	}
	out.unknown = len(res.Unmapped)
	rep := res.Report
	out.empty = len(rep.Assets) == 0 && len(rep.Findings) == 0 && len(rep.Dependencies) == 0 && len(rep.Endpoints) == 0
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return nil, err
	}
	out.body = append(body, '\n')
	return out, nil
}

func printSummary(w io.Writer, c *converted) {
	tool := c.tool
	if tool == "" {
		tool = c.format
	}
	_, _ = fmt.Fprintf(w, "%s (%s, %s): %d assets, %d findings, %d endpoints, %d components; %d records read, %d skipped\n",
		clean(c.name, 120), clean(c.format, 32), clean(tool, 80), c.stats.Assets, c.stats.Findings, c.stats.Endpoints, c.stats.Components, c.stats.Records, c.stats.Skipped)
	if c.vex > 0 {
		_, _ = fmt.Fprintf(w, "  %d VEX statements are not sent by openctem import: upload the document itself on the Import results page\n", c.vex)
	}
	if c.unknown > 0 {
		_, _ = fmt.Fprintf(w, "  %d fields of the input are not mapped (a newer tool version?)\n", c.unknown)
	}
	for i, is := range c.issues {
		if i == 10 {
			_, _ = fmt.Fprintf(w, "  ... %d more problems\n", len(c.issues)-10)
			break
		}
		_, _ = fmt.Fprintf(w, "  %s\n", clean(is, 300))
	}
}

// writeFile writes a report readable by its owner only.
func writeFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the user names the file
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readFileLimited(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the user names the file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return data, nil
}

// limitedReader fails, instead of stopping quietly, past its limit.
type limitedReader struct {
	r    io.Reader
	left int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("the input is larger than %d MiB: split it", MaxInputBytes>>20)
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

func displayName(in string) string {
	if in == "-" {
		return "stdin"
	}
	return in
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	return clean(p, 120)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// clean makes text from an input or a server safe to print: control
// characters (terminal escapes) become spaces, and it is cut to n bytes.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = s[:n]
		for len(s) > 0 && !utf8Valid(s) {
			s = s[:len(s)-1]
		}
		s += "..."
	}
	return s
}
