package legacyv1

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

// TestNoAgentVocabularyOutsideLegacy fails on an identifier or string literal
// in the SDK's (non-test) Go code that uses the pre-sensor "agent" vocabulary
// outside the places allowed to: this package, the rename tooling and the
// codemod (RFC-023 §9.5: complete rename, no permanent half-aliases). It is
// the SDK's counterpart of the API's tools/lint/sensorvocab rule.
func TestNoAgentVocabularyOutsideLegacy(t *testing.T) {
	root := moduleRoot(t)
	userAgent := regexp.MustCompile(`(?i)user[-_ ]?agent`)
	hasAgent := func(s string) bool {
		return strings.Contains(strings.ToLower(userAgent.ReplaceAllString(s, "")), "agent")
	}

	// Allowed directories (slash paths relative to the module root).
	allowedDir := func(rel string) bool {
		dir := filepath.ToSlash(filepath.Dir(rel))
		return dir == "pkg/sensorproto/legacyv1" ||
			strings.HasPrefix(rel, "scripts/rename/") ||
			strings.HasPrefix(rel, "internal/sensorrename/") ||
			strings.HasPrefix(rel, "cmd/sensor-migrate/")
	}
	// Literals allowed elsewhere, by file: header names a redirect must strip
	// (any service may use them, not only ours).
	allowedLiteral := map[string]map[string]bool{
		"pkg/httpsec/ssrf.go": {`"X-Agent-Key"`: true, `"X-Agent-API-Key"`: true},
		// An English word of the pairing SAS list, fixed by the protocol
		// (its digest is pinned in the shared test vectors).
		"pkg/sensorproto/pairing/words.go": {`"agent"`: true},
	}
	// Struct tags keeping the v1 "agent_id" key: protocol v1 wire types, and
	// the Legacy* fields that read pre-rename configuration and credentials.
	allowedTag := func(rel, field, tag string) bool {
		if field == "LegacySensorID" {
			return true
		}
		if field != "SensorID" || !strings.Contains(tag, `json:"`+FieldSensorID) {
			return false
		}
		switch rel {
		case "pkg/platform/bootstrap.go", // RegistrationResponse
			"pkg/platform/platform.go", // LeaseInfo
			"pkg/client/client.go":     // exposure ingest body
			return true
		}
		return false
	}

	fset := token.NewFileSet()
	var problems []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if allowedDir(rel) {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		tags := map[*ast.BasicLit]string{} // tag literal -> field name
		ast.Inspect(f, func(n ast.Node) bool {
			if fl, ok := n.(*ast.Field); ok && fl.Tag != nil {
				name := ""
				if len(fl.Names) > 0 {
					name = fl.Names[0].Name
				}
				tags[fl.Tag] = name
			}
			return true
		})
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.Ident:
				if hasAgent(x.Name) {
					problems = append(problems, fset.Position(x.Pos()).String()+": identifier "+x.Name)
				}
			case *ast.BasicLit:
				if x.Kind != token.STRING || !hasAgent(x.Value) {
					return true
				}
				if field, isTag := tags[x]; isTag {
					if !allowedTag(rel, field, x.Value) {
						problems = append(problems, fset.Position(x.Pos()).String()+": struct tag "+x.Value)
					}
					return true
				}
				if !allowedLiteral[rel][x.Value] {
					problems = append(problems, fset.Position(x.Pos()).String()+": string "+x.Value)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Errorf("pre-sensor vocabulary outside pkg/sensorproto/legacyv1: %s", p)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
