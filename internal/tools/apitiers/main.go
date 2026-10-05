// Command apitiers prints the stability tier of every public package of a
// module tree, from its package documentation (docs/STABILITY.md):
//
//	<package directory, slash-separated, relative to the root>\t<tier>
//
// The tier is "Deprecated" when the package comment has a paragraph
// starting with "Deprecated:", else the first word after "Stability:" in
// the package comment (Stable, Beta, Frozen, Internal-bound), else
// "missing". Packages under an internal/ directory, testdata and main
// packages are skipped. scripts/check-api-compat.sh uses it to weigh
// incompatible changes by tier.
//
// Usage: go run ./internal/tools/apitiers [ROOT]
package main

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var tierRE = regexp.MustCompile(`(?m)^Stability:\s*([A-Za-z-]+)`)

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	tiers, err := scan(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "apitiers:", err)
		os.Exit(1)
	}
	dirs := make([]string, 0, len(tiers))
	for d := range tiers {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fmt.Printf("%s\t%s\n", d, tiers[d])
	}
}

// scan returns the tier of every public library package under root.
func scan(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != root && (name == "internal" || name == "testdata" || name == "vendor" ||
			strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
			return filepath.SkipDir
		}
		tier, ok, err := packageTier(path)
		if err != nil || !ok {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = tier
		return nil
	})
	return out, err
}

// packageTier reads the package comment of the library package in dir
// (ok false: no Go package, or a main package).
func packageTier(dir string) (string, bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", false, err
	}
	docs := map[string]*strings.Builder{}
	fset := token.NewFileSet()
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.ParseComments|parser.PackageClauseOnly)
		if err != nil {
			return "", false, err
		}
		b := docs[f.Name.Name]
		if b == nil {
			b = &strings.Builder{}
			docs[f.Name.Name] = b
		}
		if f.Doc != nil {
			b.WriteString(f.Doc.Text())
			b.WriteString("\n")
		}
	}
	for name, b := range docs {
		if name == "main" || strings.HasSuffix(name, "_test") {
			continue
		}
		text := b.String()
		for _, para := range strings.Split(text, "\n\n") {
			if strings.HasPrefix(strings.TrimSpace(para), "Deprecated:") {
				return "Deprecated", true, nil
			}
		}
		if m := tierRE.FindStringSubmatch(text); m != nil {
			return m[1], true, nil
		}
		return "missing", true, nil
	}
	return "", false, nil
}
