// Package sensorrename is the type-aware "agent" -> "sensor" rename shared by
// the SDK's own rename script (scripts/rename/sensorrename) and the codemod
// third parties run on their code (cmd/sensor-migrate). RFC-023 §9.5.
//
// Both use one naming function, NewName, so the codemod maps every old SDK
// identifier to exactly the name the SDK gave it.
//
// Identifiers are resolved with go/types (the go/packages loader gopls uses):
// a local variable called `agent` in a caller's code is a different object
// from core.Agent and is never touched. The rename is a pure function of the
// identifier, so an interface method and its implementations, a struct field
// and every composite-literal key, all land on the same new name without
// tracking the relationships explicitly. Before anything is written each
// renamed occurrence is checked against the scope it sits in (and, for a
// field or method selection, against the receiver's method set): if the new
// name already means something else there, the rename reports a conflict and
// writes nothing.
//
// String literals and struct tags are never changed: they are wire and
// storage contracts (see pkg/sensorproto/legacyv1).
package sensorrename

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

// SDKModule is the module whose identifiers the rename covers.
const SDKModule = "github.com/openctemio/sdk-go"

// keep lists identifiers that contain "agent" but do not mean a sensor.
var keep = map[string]bool{}

// overrides are names whose mechanical rename would read wrongly.
var overrides = map[string]string{}

var userAgentRe = regexp.MustCompile(`(?i)user[-_ ]?agent`)

// NewName returns the sensor-vocabulary form of an identifier (agent ->
// sensor, preserving case; "user agent" in any spelling is left alone).
func NewName(name string) string {
	if keep[name] {
		return name
	}
	if v, ok := overrides[name]; ok {
		return v
	}
	return replaceWord(name)
}

// NeedsRename reports whether NewName changes name.
func NeedsRename(name string) bool { return NewName(name) != name }

func replaceWord(s string) string {
	var protected []string
	s = userAgentRe.ReplaceAllStringFunc(s, func(m string) string {
		protected = append(protected, m)
		return fmt.Sprintf("\x00%d\x00", len(protected)-1)
	})
	s = strings.ReplaceAll(s, "AGENT", "SENSOR")
	s = strings.ReplaceAll(s, "Agent", "Sensor")
	s = strings.ReplaceAll(s, "agent", "sensor")
	for i, p := range protected {
		s = strings.Replace(s, fmt.Sprintf("\x00%d\x00", i), p, 1)
	}
	return s
}

// RenamePath renames every element of a slash-separated path.
func RenamePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = NewName(s)
	}
	return strings.Join(parts, "/")
}

// Comment rewriting. Protected spans are left byte for byte:
//   - "user agent" in any spelling (the HTTP header);
//   - protocol v1 vocabulary: the /api/v1/agent routes, X-Agent-* headers,
//     the x-agent-id gRPC key, the agent_id / agent_preference JSON keys;
//   - ALL-CAPS environment variable names (AGENT_ID, AGENT_ALLOW_PRIVATE_TARGETS),
//     which name the configuration of installations that predate the rename;
//   - the sensor binary's repository and released image name
//     (openctemio/agent), and the old credentials file name;
//   - comments that name the old vocabulary on purpose (the rename itself,
//     quoted values), so re-running the rename keeps them.
var protectRes = []*regexp.Regexp{
	userAgentRe,
	regexp.MustCompile(`/api/v1/agent(/[A-Za-z0-9_{}./-]*)?\b`),
	regexp.MustCompile(`(?i)\bx-agent-[a-z-]+`),
	regexp.MustCompile(`\bagent_(id|preference)\b`),
	regexp.MustCompile(`\b[A-Z0-9_]*AGENT[A-Z0-9_]*\b`),
	regexp.MustCompile(`openctemio/agent\b[:A-Za-z0-9_.-]*`),
	regexp.MustCompile(`agent-credentials\.json`),
	regexp.MustCompile(`\bagent ?(→|->) ?sensor\b`),
	regexp.MustCompile("[\"'`]agents?[A-Za-z0-9_.:*-]*[\"'`]"),
}

// articleRe fixes "an agent" -> "an sensor" into "a sensor".
var articleRe = regexp.MustCompile(`\b([Aa])n( [Ss]ensor)`)

var identRe = regexp.MustCompile(`\b[A-Za-z_][A-Za-z0-9_]*\b`)

// RewriteComment renames the agent vocabulary in a comment's prose and
// identifier references, keeping the protected spans.
func RewriteComment(text string) string {
	var protected []string
	for _, re := range protectRes {
		text = re.ReplaceAllStringFunc(text, func(m string) string {
			protected = append(protected, m)
			return fmt.Sprintf("\x00%d\x00", len(protected)-1)
		})
	}
	text = identRe.ReplaceAllStringFunc(text, func(w string) string {
		if !strings.Contains(strings.ToLower(w), "agent") {
			return w
		}
		return NewName(w)
	})
	text = articleRe.ReplaceAllString(text, "$1$2")
	for i := len(protected) - 1; i >= 0; i-- {
		text = strings.Replace(text, fmt.Sprintf("\x00%d\x00", i), protected[i], 1)
	}
	return text
}

// KeepDirective marks a comment group whose old-vocabulary wording is
// intentional.
const KeepDirective = "//sensorrename:keep"

// Edit replaces src[Off:End] with Text.
type Edit struct {
	Off, End int
	Text     string
}

// Options configures a rename pass.
type Options struct {
	// Target reports whether an object's declaring package is covered by the
	// rename: its own identifiers for the SDK, the SDK's for the codemod.
	Target func(pkgPath string) bool
	// SkipFile excludes files (absolute paths) from editing.
	SkipFile func(file string) bool
	// Comments also rewrites comments (the SDK's own rename only).
	Comments bool
}

// Result is every edit of a pass, collected before anything is written.
type Result struct {
	Edits     map[string]map[int]Edit // file -> offset -> edit
	Conflicts []string
}

// Load type-checks the packages matched by patterns in dir, tests included.
func Load(dir string, patterns ...string) ([]*packages.Package, error) {
	return LoadTags(dir, "", patterns...)
}

// LoadTags is Load for one build configuration: tags is a comma-separated
// build tag list ("" for the default build). Files behind a build tag are
// only seen by a load with that tag, so a module with tagged files is
// loaded once per configuration and the results merged (Result.Merge).
func LoadTags(dir, tags string, patterns ...string) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedModule,
		Dir:   dir,
		Tests: true,
	}
	if tags != "" {
		cfg.BuildFlags = []string{"-tags=" + tags}
	}
	if len(patterns) == 0 {
		patterns = []string{"./..."}
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	var errs []string
	packages.Visit(pkgs, nil, func(p *packages.Package) {
		for _, e := range p.Errors {
			errs = append(errs, e.Error())
		}
	})
	if len(errs) > 0 {
		sort.Strings(errs)
		return nil, fmt.Errorf("the code does not type-check:\n  %s", strings.Join(dedupe(errs), "\n  "))
	}
	return pkgs, nil
}

func dedupe(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// Collect gathers the edits of a rename pass over pkgs.
func Collect(pkgs []*packages.Package, opt Options) *Result {
	c := &collector{opt: opt, res: &Result{Edits: map[string]map[int]Edit{}}, seen: map[string]bool{}}
	for _, pkg := range pkgs {
		c.collect(pkg)
	}
	sort.Strings(c.res.Conflicts)
	c.res.Conflicts = dedupe(c.res.Conflicts)
	return c.res
}

type collector struct {
	opt  Options
	res  *Result
	seen map[string]bool
}

func (c *collector) add(fset *token.FileSet, pos token.Pos, oldLen int, text string) {
	p := fset.Position(pos)
	if c.opt.SkipFile != nil && c.opt.SkipFile(p.Filename) {
		return
	}
	m := c.res.Edits[p.Filename]
	if m == nil {
		m = map[int]Edit{}
		c.res.Edits[p.Filename] = m
	}
	m[p.Offset] = Edit{Off: p.Offset, End: p.Offset + oldLen, Text: text}
}

func (c *collector) target(obj types.Object) bool {
	if pn, ok := obj.(*types.PkgName); ok {
		return c.opt.Target(pn.Imported().Path())
	}
	if obj.Pkg() == nil {
		return false
	}
	return c.opt.Target(obj.Pkg().Path())
}

// renames reports whether obj is renamed by this pass. Besides objects
// declared in a target package, that covers an embedded field whose name
// comes from a renamed target type (type Mine struct{ *core.BaseAgent }).
func (c *collector) renames(name string, obj types.Object) bool {
	if obj == nil || !NeedsRename(name) {
		return false
	}
	if c.target(obj) {
		return true
	}
	if v, ok := obj.(*types.Var); ok && v.Embedded() {
		t := v.Type()
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
		}
		if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil {
			return c.opt.Target(n.Obj().Pkg().Path()) && n.Obj().Name() == name
		}
	}
	return false
}

func (c *collector) collect(pkg *packages.Package) {
	if pkg.TypesInfo == nil {
		return
	}
	for id, obj := range pkg.TypesInfo.Defs {
		c.ident(pkg, id, obj)
	}
	for id, obj := range pkg.TypesInfo.Uses {
		c.ident(pkg, id, obj)
	}
	for sel, s := range pkg.TypesInfo.Selections {
		c.selection(pkg, sel, s)
	}
	for _, f := range pkg.Syntax {
		name := pkg.Fset.Position(f.Pos()).Filename
		if c.seen[name] {
			continue
		}
		c.seen[name] = true
		c.file(pkg, f)
	}
}

func (c *collector) ident(pkg *packages.Package, id *ast.Ident, obj types.Object) {
	if !c.renames(id.Name, obj) {
		return
	}
	nn := NewName(id.Name)
	c.add(pkg.Fset, id.Pos(), len(id.Name), nn)
	// Fields and methods are not in lexical scope; selection() checks them.
	if v, ok := obj.(*types.Var); ok && v.IsField() {
		return
	}
	if fn, ok := obj.(*types.Func); ok && fn.Type().(*types.Signature).Recv() != nil {
		return
	}
	if s := pkg.Types.Scope().Innermost(id.Pos()); s != nil {
		if _, other := s.LookupParent(nn, id.Pos()); other != nil && other != obj {
			c.res.Conflicts = append(c.res.Conflicts, fmt.Sprintf("%s: %s -> %s collides with %s",
				pkg.Fset.Position(id.Pos()), id.Name, nn, other))
		}
	}
}

// selection checks that x.NewName does not already resolve to a different
// field or method of x's type (for example one the caller declared on a
// struct that embeds an SDK type), which would silently change meaning.
func (c *collector) selection(pkg *packages.Package, sel *ast.SelectorExpr, s *types.Selection) {
	obj := s.Obj()
	if !c.renames(sel.Sel.Name, obj) {
		return
	}
	nn := NewName(sel.Sel.Name)
	if other, _, _ := types.LookupFieldOrMethod(s.Recv(), true, pkg.Types, nn); other != nil && other != obj {
		c.res.Conflicts = append(c.res.Conflicts, fmt.Sprintf("%s: .%s -> .%s collides with %s",
			pkg.Fset.Position(sel.Sel.Pos()), sel.Sel.Name, nn, other))
	}
}

func (c *collector) file(pkg *packages.Package, f *ast.File) {
	fset := pkg.Fset
	if NeedsRename(f.Name.Name) && c.opt.Target(pkg.PkgPath) {
		c.add(fset, f.Name.Pos(), len(f.Name.Name), NewName(f.Name.Name))
	}
	for _, imp := range f.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if c.opt.Target(path) && NeedsRename(path[len(SDKModule):]) {
			c.add(fset, imp.Path.Pos(), len(imp.Path.Value), `"`+SDKModule+RenamePath(path[len(SDKModule):])+`"`)
		}
	}
	if !c.opt.Comments {
		return
	}
	for _, cg := range f.Comments {
		if keepGroup(cg) {
			continue
		}
		for _, cm := range cg.List {
			if nt := RewriteComment(cm.Text); nt != cm.Text {
				c.add(fset, cm.Pos(), len(cm.Text), nt)
			}
		}
	}
}

func keepGroup(cg *ast.CommentGroup) bool {
	for _, c := range cg.List {
		if strings.HasPrefix(c.Text, KeepDirective) {
			return true
		}
	}
	return false
}

// InModule reports whether pkgPath is module or one of its packages (test
// variants included).
func InModule(module, pkgPath string) bool {
	return pkgPath == module || strings.HasPrefix(pkgPath, module+"/") ||
		strings.HasPrefix(pkgPath, module+".") || strings.HasPrefix(pkgPath, module+" ")
}

// Apply returns file's content with edits applied and gofmt'ed.
func Apply(file string, edits map[int]Edit) (before, after []byte, err error) {
	src, err := os.ReadFile(file) //nolint:gosec // files of the module being renamed
	if err != nil {
		return nil, nil, err
	}
	list := make([]Edit, 0, len(edits))
	for _, e := range edits {
		list = append(list, e)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Off > list[j].Off })
	out := append([]byte(nil), src...)
	for _, e := range list {
		out = append(out[:e.Off:e.Off], append([]byte(e.Text), out[e.End:]...)...)
	}
	if formatted, ferr := format.Source(out); ferr == nil {
		out = formatted
	}
	return src, out, nil
}

// Merge adds other's edits and conflicts to r. Edits are keyed by file and
// offset, and the name of an occurrence does not depend on the build
// configuration, so an occurrence seen by several loads is edited once.
func (r *Result) Merge(other *Result) {
	for f, m := range other.Edits {
		dst := r.Edits[f]
		if dst == nil {
			dst = map[int]Edit{}
			r.Edits[f] = dst
		}
		for off, e := range m {
			dst[off] = e
		}
	}
	r.Conflicts = append(r.Conflicts, other.Conflicts...)
	sort.Strings(r.Conflicts)
	r.Conflicts = dedupe(r.Conflicts)
}

// Files returns the edited files in a stable order.
func (r *Result) Files() []string {
	files := make([]string, 0, len(r.Edits))
	for f := range r.Edits {
		files = append(files, f)
	}
	sort.Strings(files)
	return files
}

// Count is the number of edits.
func (r *Result) Count() int {
	n := 0
	for _, m := range r.Edits {
		n += len(m)
	}
	return n
}

// UnifiedDiff renders a unified diff of before -> after. Identifier renames
// never add or remove lines, so lines are compared position by position; if
// the counts ever differ the whole file is shown as replaced.
func UnifiedDiff(name string, before, after []byte) string {
	a, b := splitLines(before), splitLines(after)
	if len(a) != len(b) {
		var buf bytes.Buffer
		fmt.Fprintf(&buf, "--- a/%s\n+++ b/%s\n", filepath.ToSlash(name), filepath.ToSlash(name))
		fmt.Fprintf(&buf, "@@ -1,%d +1,%d @@\n", len(a), len(b))
		for _, l := range a {
			buf.WriteString("-" + l + "\n")
		}
		for _, l := range b {
			buf.WriteString("+" + l + "\n")
		}
		return buf.String()
	}
	var changed []int
	for i := range a {
		if a[i] != b[i] {
			changed = append(changed, i)
		}
	}
	return renderHunks(name, a, b, changed)
}

// renderHunks writes hunks grouping changed lines with three lines of context,
// each run of changed lines as its "-" lines followed by its "+" lines.
func renderHunks(name string, a, b []string, changed []int) string {
	const ctx = 3
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "--- a/%s\n+++ b/%s\n", filepath.ToSlash(name), filepath.ToSlash(name))
	isChanged := map[int]bool{}
	for _, c := range changed {
		isChanged[c] = true
	}
	for i := 0; i < len(changed); {
		j := i
		for j+1 < len(changed) && changed[j+1]-changed[j] <= 2*ctx {
			j++
		}
		start := max(changed[i]-ctx, 0)
		end := min(changed[j]+ctx, len(a)-1)
		fmt.Fprintf(&buf, "@@ -%d,%d +%d,%d @@\n", start+1, end-start+1, start+1, end-start+1)
		for k := start; k <= end; {
			if !isChanged[k] {
				buf.WriteString(" " + a[k] + "\n")
				k++
				continue
			}
			run := k
			for run <= end && isChanged[run] {
				run++
			}
			for x := k; x < run; x++ {
				buf.WriteString("-" + a[x] + "\n")
			}
			for x := k; x < run; x++ {
				buf.WriteString("+" + b[x] + "\n")
			}
			k = run
		}
		i = j + 1
	}
	return buf.String()
}

func splitLines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}
