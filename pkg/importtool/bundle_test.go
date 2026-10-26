package importtool_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openctemio/sdk-go/pkg/importtool"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// reconFiles loads the synthetic reconFTW v4 directory as task files under in/recon.
func reconFiles(t *testing.T) map[string][]byte {
	t.Helper()
	root := filepath.Join("testdata", "reconftw", "v4")
	files := map[string][]byte{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		files["in/recon/"+filepath.ToSlash(rel)] = b
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func reconTask() tool.Task {
	return tool.Task{
		Inputs: []tool.Input{input("recon", "in/recon")},
		Config: []byte(`{"format":"reconftw"}`),
	}
}

// A results directory of the task is one bundle, through the tool contract's
// checks, pinned by a golden report.
func TestImportTool_ReconBundle(t *testing.T) {
	res := testkit.Run(t, importtool.New(), reconTask(), testkit.Options{Files: reconFiles(t)})
	res.RequireStatus(t, tool.StatusOK)
	if len(res.Report.Assets) == 0 || len(res.Report.Endpoints) == 0 {
		t.Fatalf("assets %d endpoints %d", len(res.Report.Assets), len(res.Report.Endpoints))
	}
	res.Golden(t, filepath.Join("testdata", "reconftw.ctis.golden.json"))
}

// People and credential files are never opened: the sentinel in osint/ is in
// neither the report nor the logs, and the skip is logged.
func TestImportTool_ReconOsintNeverRead(t *testing.T) {
	files := reconFiles(t)
	if !strings.Contains(string(files["in/recon/osint/emails.txt"]), "SENTINEL") {
		t.Fatal("fixture lost its sentinel")
	}
	res := testkit.Run(t, importtool.New(), reconTask(), testkit.Options{Files: files})
	res.RequireStatus(t, tool.StatusOK)
	b, _ := json.Marshal(res.Report)
	logs, _ := json.Marshal(res.Logs)
	if strings.Contains(string(b), "SENTINEL") || strings.Contains(string(logs), "SENTINEL") {
		t.Fatal("osint content reached the output")
	}
	if !strings.Contains(string(logs), "osint/emails.txt") {
		t.Fatal("the skipped file is not logged")
	}
}

func TestImportTool_ReconRefusals(t *testing.T) {
	cases := map[string]struct {
		task  tool.Task
		files map[string][]byte
	}{
		"two inputs": {tool.Task{Inputs: []tool.Input{input("a", "in/recon"), input("b", "in/recon")}, Config: []byte(`{"format":"reconftw"}`)}, nil},
		"not a bundle": {tool.Task{Inputs: []tool.Input{input("x", "in/x")}, Config: []byte(`{"format":"reconftw"}`)},
			map[string][]byte{"in/x/readme.txt": []byte("hello")}},
		"a file, not a directory": {tool.Task{Inputs: []tool.Input{input("f", "in/f.txt")}, Config: []byte(`{"format":"reconftw"}`)},
			map[string][]byte{"in/f.txt": []byte("hello")}},
		"outside the task": {tool.Task{Inputs: []tool.Input{input("p", "../etc")}, Config: []byte(`{"format":"reconftw"}`)}, nil},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			files := c.files
			if name == "two inputs" {
				files = reconFiles(t)
			}
			res := testkit.Run(t, importtool.New(), c.task, testkit.Options{Files: files})
			res.RequireStatus(t, tool.StatusFailed)
			if res.Err == nil || res.Err.Class != tool.InvalidInput {
				t.Fatalf("error %+v", res.Err)
			}
		})
	}
}
