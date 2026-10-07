package conformance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"time"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/testkit"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// Bounds a fuzzed parse must stay within.
const (
	fuzzMaxInput   = 1 << 20
	fuzzMaxRecords = tool.DefaultMaxRecords
)

// outputParser is the parse the runtime applies to an exec tool's output,
// returning its result as canonical JSON.
type outputParser func(ctx context.Context, data []byte) ([]byte, int, error)

// parserFor returns the parser of a format and a minimal valid seed.
func parserFor(format string) (outputParser, []byte, bool) {
	report := func(r *ctis.Report) ([]byte, int, error) {
		if r == nil {
			return nil, 0, nil
		}
		// Normalized: ids and timestamps a parser draws per call are not
		// non-determinism.
		b, err := testkit.Normalize(r)
		return b, len(r.Assets) + len(r.Findings) + len(r.Dependencies), err
	}
	switch format {
	case tool.OutputSARIF:
		return func(ctx context.Context, data []byte) ([]byte, int, error) {
				r, err := (&core.SARIFParser{}).Parse(ctx, data, &core.ParseOptions{})
				if err != nil {
					return nil, 0, err
				}
				return report(r)
			}, []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"t","rules":[{"id":"R1"}]}},"results":[{"ruleId":"R1","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":1}}}]}]}]}`),
			true
	case tool.OutputCTIS:
		return func(_ context.Context, data []byte) ([]byte, int, error) {
				var r ctis.Report
				d := json.NewDecoder(bytes.NewReader(data))
				d.DisallowUnknownFields()
				if err := d.Decode(&r); err != nil {
					return nil, 0, err
				}
				if err := r.Validate(); err != nil {
					return nil, 0, err
				}
				return report(&r)
			}, []byte(`{"version":"1.4","metadata":{"timestamp":"2026-01-01T00:00:00Z"},"findings":[{"type":"vulnerability","title":"t","severity":"high"}]}`),
			true
	case tool.OutputJSONLCTIS:
		return func(_ context.Context, data []byte) ([]byte, int, error) {
				var out bytes.Buffer
				n := 0
				for _, line := range bytes.Split(data, []byte("\n")) {
					if len(bytes.TrimSpace(line)) == 0 {
						continue
					}
					var rec map[string]json.RawMessage
					if err := json.Unmarshal(line, &rec); err != nil {
						return nil, 0, err
					}
					b, _ := json.Marshal(rec)
					out.Write(b)
					n++
				}
				return out.Bytes(), n, nil
			}, []byte(`{"kind":"finding","data":{"type":"vulnerability","title":"t","severity":"high"}}` + "\n"),
			true
	}
	f := importer.Format(format)
	for _, known := range []importer.Format{importer.FormatNuclei, importer.FormatSemgrep, importer.FormatTrivy,
		importer.FormatBetterleaks, importer.FormatGitleaks, importer.FormatGrype, importer.FormatZAP, importer.FormatVuls,
		importer.FormatCycloneDX, importer.FormatSPDX, importer.FormatOSV, importer.FormatCSAF, importer.FormatOpenVEX,
		importer.FormatNessus, importer.FormatQualys, importer.FormatDefectDojo} {
		if f != known {
			continue
		}
		return func(ctx context.Context, data []byte) ([]byte, int, error) {
			res, err := importer.Parse(ctx, bytes.NewReader(data), importer.Options{Format: f, Now: time.Unix(0, 0).UTC()})
			if err != nil {
				return nil, 0, err
			}
			res.Report.Metadata.ID = ""
			return report(res.Report)
		}, []byte("{}"), true
	}
	return nil, nil, false
}

// FuzzOutput fuzzes the parser of an exec-profile tool's output format for
// d: seeds are the files of the tool's fuzz/ directory and a minimal valid
// document, mutated with a fixed-seed generator. A panic, two parses of
// the same input that differ, or a result above the record cap fails; the
// input is saved under fuzz/crashers/. Adapter tools (records checked one
// by one by the runtime) are not fuzzed here.
func FuzzOutput(t T, m tool.Manifest, dir string, d time.Duration) {
	t.Helper()
	if m.Run == nil || m.Run.Profile != tool.ProfileExec || m.Run.Output == nil {
		t.Logf("Fuzz: %s is not an exec-profile tool; its records are checked one by one by the runtime", m.Name)
		return
	}
	parse, seed, ok := parserFor(m.Run.Output.Format)
	if !ok {
		t.Logf("Fuzz: no parser to fuzz for the %s format", m.Run.Output.Format)
		return
	}
	seeds := [][]byte{seed}
	files, _ := filepath.Glob(filepath.Join(dir, "fuzz", "*"))
	for _, f := range files {
		if b, err := os.ReadFile(f); err == nil && len(b) <= fuzzMaxInput { //nolint:gosec // the tool's own corpus
			seeds = append(seeds, b)
		}
	}
	rng := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // reproducible mutations, not security
	deadline := time.Now().Add(d)
	runs := 0
	for time.Now().Before(deadline) {
		in := mutate(rng, seeds[rng.IntN(len(seeds))])
		runs++
		if msg := fuzzOne(parse, in); msg != "" {
			sum := sha256.Sum256(in)
			path := filepath.Join(dir, "fuzz", "crashers", hex.EncodeToString(sum[:8]))
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err == nil {
				_ = os.WriteFile(path, in, 0o600)
			}
			t.Errorf("Fuzz: %s (input saved to %s)", msg, path)
			return
		}
	}
	t.Logf("Fuzz: %d inputs of the %s parser, no failure", runs, m.Run.Output.Format)
}

func fuzzOne(parse outputParser, in []byte) (msg string) {
	defer func() {
		if v := recover(); v != nil {
			msg = fmt.Sprintf("the parser panicked: %v", v)
		}
	}()
	ctx := context.Background()
	a, n, errA := parse(ctx, in)
	b, _, errB := parse(ctx, in)
	if (errA == nil) != (errB == nil) || !bytes.Equal(a, b) {
		return "two parses of the same input differ (non-deterministic output)"
	}
	if n > fuzzMaxRecords {
		return fmt.Sprintf("%d records from %d bytes, above the cap of %d", n, len(in), fuzzMaxRecords)
	}
	return ""
}

// interesting are fragments that stress JSON and text parsers.
var interesting = [][]byte{
	[]byte("{"), []byte("}"), []byte("["), []byte("]"), []byte(`"`), []byte(`\u0000`), []byte("\x00"),
	[]byte("1e999999"), []byte("-0"), []byte("null"), []byte(`"\ud800"`), []byte("\u202e"),
	bytes.Repeat([]byte("["), 200), bytes.Repeat([]byte("a"), 4096),
}

// mutate returns a mutation of in: a flip, a cut, a copy or an insertion.
func mutate(rng *rand.Rand, in []byte) []byte {
	out := bytes.Clone(in)
	for range 1 + rng.IntN(4) {
		if len(out) == 0 {
			out = append(out, interesting[rng.IntN(len(interesting))]...)
			continue
		}
		i := rng.IntN(len(out))
		switch rng.IntN(5) {
		case 0:
			out[i] ^= byte(1 << rng.IntN(8))
		case 1:
			j := i + rng.IntN(len(out)-i)
			out = append(out[:i], out[j:]...)
		case 2:
			j := i + rng.IntN(min(len(out)-i, 256))
			out = append(out[:j], append(bytes.Clone(out[i:j]), out[j:]...)...)
		case 3:
			frag := interesting[rng.IntN(len(interesting))]
			out = append(out[:i], append(bytes.Clone(frag), out[i:]...)...)
		default:
			out = out[:i]
		}
		if len(out) > fuzzMaxInput {
			out = out[:fuzzMaxInput]
		}
	}
	return out
}
