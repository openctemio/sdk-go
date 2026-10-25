// Package refgate keeps internal design references (RFC numbers, research
// notes, decision and question ids) out of anything a user or operator
// reads: warnings, errors, logs, flag and setting descriptions, schemas.
// Comments and test files may keep them.
package refgate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var internalRef = regexp.MustCompile(`RFC-?\d+|research/\d+|\((?:Q|D)\d+\b[^)]*\)|\bQ\d+ \([a-z]\)|[Oo]wner decision|phase P\d`)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", "..")
}

func skipDir(name string) bool {
	return name == ".git" || name == "node_modules" || name == "vendor" || name == "testdata"
}

// TestNoInternalReferencesInStrings fails when a non-test Go string literal
// or a shipped JSON file cites an internal design document.
func TestNoInternalReferencesInStrings(t *testing.T) {
	root := repoRoot(t)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go"):
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				t.Errorf("parse %s: %v", rel, perr)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if l, ok := n.(*ast.BasicLit); ok && l.Kind == token.STRING && internalRef.MatchString(l.Value) {
					t.Errorf("%s:%d: string cites an internal reference (%q); say it plainly instead",
						rel, fset.Position(l.Pos()).Line, internalRef.FindString(l.Value))
				}
				return true
			})
		case strings.HasSuffix(p, ".json") && strings.HasPrefix(rel, "pkg"+string(filepath.Separator)):
			b, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			if m := internalRef.Find(b); m != nil {
				t.Errorf("%s: cites an internal reference (%q)", rel, m)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPatternMatches(t *testing.T) {
	for _, s := range []string{"(api RFC-040 Q3)", "see research/25", "(Q4 (a))", "owner decision D1", "phase P0"} {
		if !internalRef.MatchString(s) {
			t.Errorf("pattern misses %q", s)
		}
	}
	for _, s := range []string{"RFC 7644", "RFC 9110 requires", "Q&A"} {
		if internalRef.MatchString(s) {
			t.Errorf("pattern flags %q", s)
		}
	}
}
