package tool

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/ctis/importer/mapping"
	"gopkg.in/yaml.v3"
)

// Output formats of the exec profile that need a mapping file
// (run.output.mapping): any JSON document or JSON Lines output, turned
// into CTIS by the declarative mapping language of ctis/importer/mapping.
const (
	OutputJSON  = "json"
	OutputJSONL = "jsonl"
)

// ImporterFormats are the named formats an exec-profile tool may write:
// the formats of ctis/importer, parsed with no code in the tool.
func ImporterFormats() []string {
	fs := []importer.Format{
		importer.FormatNuclei, importer.FormatSemgrep, importer.FormatTrivy, importer.FormatBetterleaks,
		importer.FormatGitleaks, importer.FormatGrype, importer.FormatZAP, importer.FormatVuls,
		importer.FormatCycloneDX, importer.FormatSPDX, importer.FormatOSV, importer.FormatCSAF,
		importer.FormatOpenVEX, importer.FormatNessus, importer.FormatQualys, importer.FormatDefectDojo,
	}
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = string(f)
	}
	return out
}

// outputFormats are every exec-profile output format.
func outputFormats() []string {
	return append([]string{OutputCTIS, OutputSARIF, OutputJSONLCTIS, OutputJSON, OutputJSONL}, ImporterFormats()...)
}

// MaxMappingBytes bounds a mapping file.
const MaxMappingBytes = 256 << 10

// LoadMappingFile reads the mapping file of an exec-profile manifest from
// dir: JSON or YAML, a regular file inside dir (no symlink), at most
// MaxMappingBytes. When want is set the mapping's digest must equal it, so
// a file changed after the manifest was loaded is refused.
func LoadMappingFile(dir, rel, want string) (*mapping.Mapping, error) {
	if msg := checkRelPath(rel); msg != "" {
		return nil, fmt.Errorf("mapping %q: %s", rel, msg)
	}
	path := filepath.Join(dir, filepath.FromSlash(rel))
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("mapping %q: not a regular file", rel)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxMappingBytes+1))
	if err != nil {
		return nil, fmt.Errorf("mapping: %w", err)
	}
	if len(data) > MaxMappingBytes {
		return nil, fmt.Errorf("mapping %q: larger than %d bytes", rel, MaxMappingBytes)
	}
	js, err := mappingJSON(data)
	if err != nil {
		return nil, fmt.Errorf("mapping %q: %w", rel, err)
	}
	mp, err := mapping.Load(js)
	if err != nil {
		return nil, fmt.Errorf("mapping %q: %w", rel, err)
	}
	if want != "" && mp.Digest() != want {
		return nil, fmt.Errorf("mapping %q changed since the manifest was loaded (digest %s, want %s)", rel, mp.Digest(), want)
	}
	return mp, nil
}

// mappingJSON returns a mapping document as JSON: JSON as it is, YAML
// converted (one document, no duplicate keys).
func mappingJSON(data []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return trimmed, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not YAML: %w", err)
	}
	var extra any
	if dec.Decode(&extra) == nil {
		return nil, fmt.Errorf("more than one YAML document")
	}
	if _, ok := doc.(map[string]any); !ok {
		return nil, fmt.Errorf("not a mapping")
	}
	return json.Marshal(doc)
}

// needsMapping reports whether an output format reads a mapping file.
func needsMapping(format string) bool {
	return slices.Contains([]string{OutputJSON, OutputJSONL}, format)
}
