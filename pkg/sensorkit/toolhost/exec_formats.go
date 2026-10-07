package toolhost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/openctemio/ctis/importer"
	"github.com/openctemio/ctis/importer/mapping"
	"github.com/openctemio/sdk-go/pkg/ctis"
	"github.com/openctemio/sdk-go/pkg/tool"
)

// maxIngestIssues bounds the parser issues an Outcome lists in its logs.
const maxIngestIssues = 10

// ingestMapped turns json or jsonl output into CTIS with the tool's mapping
// file and feeds it through the record checks. The report's tool is the
// manifest's, never the output's.
func ingestMapped(ctx context.Context, p *prepared, data []byte) error {
	if p.mapping == nil {
		return fmt.Errorf("the %s format needs a mapping file", p.m.Run.Output.Format)
	}
	_, _, maxBytes, maxRecords := p.m.Resources.Limits()
	r, st, err := p.mapping.Apply(ctx, bytes.NewReader(data), mapping.Options{
		Now:           func() time.Time { return time.Now().UTC() },
		Tool:          &ctis.Tool{Name: p.m.Name, Version: p.m.Version},
		MaxInputBytes: maxBytes, MaxRecords: maxRecords, MaxOutputs: maxRecords,
	})
	if err != nil {
		return err
	}
	for i, is := range st.Issues {
		if i == maxIngestIssues {
			break
		}
		p.notes = append(p.notes, LogLine{Level: "warn", Msg: "mapping: " + is.Message,
			Fields: map[string]any{"source": "runtime", "record": is.Record, "rule": is.Rule}})
	}
	return ingestReport(p, r)
}

// ingestNamed parses output in a named ctis/importer format and feeds it
// through the record checks. A record that names no asset goes to the
// task's only target.
func ingestNamed(ctx context.Context, p *prepared, format string, data []byte) error {
	opts := importer.Options{Format: importer.Format(format), ToolName: p.m.Name, SourceType: "scanner"}
	if len(p.task.Targets) == 1 {
		t := p.task.Targets[0]
		typ := ctis.AssetType(t.Type)
		if typ == "" {
			typ = ctis.AssetTypeUnclassified
		}
		opts.DefaultAsset = &ctis.Asset{Type: typ, Value: t.Value}
	}
	res, err := importer.Parse(ctx, bytes.NewReader(data), opts)
	if err != nil {
		return err
	}
	for i, is := range res.Issues {
		if i == maxIngestIssues {
			break
		}
		p.notes = append(p.notes, LogLine{Level: "warn", Msg: fmt.Sprintf("%s: %s", format, is.Message),
			Fields: map[string]any{"source": "runtime"}})
	}
	return ingestReport(p, res.Report)
}

func ingestReport(p *prepared, r *ctis.Report) error {
	if r == nil {
		return nil
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return ingestCTIS(p, raw)
}

func isNamedFormat(f string) bool { return slices.Contains(tool.ImporterFormats(), f) }

func isMappedFormat(f string) bool { return f == tool.OutputJSON || f == tool.OutputJSONL }
