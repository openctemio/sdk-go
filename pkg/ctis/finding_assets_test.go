package ctis

import (
	"errors"
	"strings"
	"testing"
)

func TestCheckFindingAssets(t *testing.T) {
	repo := Asset{ID: "a1", Type: AssetTypeRepository, Value: "github.com/org/app"}
	host := Asset{ID: "a2", Type: AssetTypeDomain, Value: "example.com"}

	cases := []struct {
		name       string
		report     *Report
		unresolved []int // nil: CheckFindingAssets returns nil
	}{
		{"nil report", nil, nil},
		{"no findings", &Report{}, nil},
		{"ref names an asset", &Report{Assets: []Asset{repo, host}, Findings: []Finding{{AssetRef: "a2"}, {AssetRef: "a1"}}}, nil},
		{"empty ref, exactly one asset", &Report{Assets: []Asset{repo}, Findings: []Finding{{}}}, nil},
		{"empty ref, one asset with no id", &Report{Assets: []Asset{{Type: AssetTypeRepository, Value: "x"}}, Findings: []Finding{{}}}, nil},
		{"no assets", &Report{Findings: []Finding{{}, {}}}, []int{0, 1}},
		{"empty ref, two assets is ambiguous", &Report{Assets: []Asset{repo, host}, Findings: []Finding{{AssetRef: "a1"}, {}}}, []int{1}},
		{"ref to a missing asset", &Report{Assets: []Asset{repo}, Findings: []Finding{{AssetRef: "a1"}, {AssetRef: "nope"}}}, []int{1}},
		{"asset_value is not a reference", &Report{Findings: []Finding{{AssetValue: "github.com/org/app", AssetType: AssetTypeRepository}}}, []int{0}},
		{"asset without a value is not stored", &Report{Assets: []Asset{{ID: "a1", Type: AssetTypeRepository, Value: " "}}, Findings: []Finding{{AssetRef: "a1"}}}, []int{0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckFindingAssets(tc.report)
			if tc.unresolved == nil {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			var fe *FindingAssetError
			if !errors.As(err, &fe) {
				t.Fatalf("err = %v, want *FindingAssetError", err)
			}
			if !errors.Is(err, ErrNoAssetForFindings) {
				t.Error("errors.Is(err, ErrNoAssetForFindings) = false")
			}
			if fe.Unresolved != len(tc.unresolved) || fe.Total != len(tc.report.Findings) {
				t.Errorf("unresolved/total = %d/%d, want %d/%d", fe.Unresolved, fe.Total, len(tc.unresolved), len(tc.report.Findings))
			}
			for i, want := range tc.unresolved {
				if i >= len(fe.Indices) || fe.Indices[i] != want {
					t.Errorf("indices = %v, want %v", fe.Indices, tc.unresolved)
					break
				}
			}
		})
	}
}

// The error lists a bounded number of indices and never finding content.
func TestCheckFindingAssets_ErrorIsBoundedAndContentFree(t *testing.T) {
	r := &Report{}
	for i := 0; i < 50; i++ {
		r.Findings = append(r.Findings, Finding{Title: "SECRET-TITLE", AssetValue: "secret-host"})
	}
	err := CheckFindingAssets(r)
	var fe *FindingAssetError
	if !errors.As(err, &fe) {
		t.Fatalf("err = %v", err)
	}
	if fe.Unresolved != 50 || len(fe.Indices) != maxReportedIndices {
		t.Errorf("unresolved = %d, indices = %v", fe.Unresolved, fe.Indices)
	}
	msg := err.Error()
	if strings.Contains(msg, "SECRET") || strings.Contains(msg, "secret-host") {
		t.Errorf("error leaks finding content: %s", msg)
	}
	if !strings.Contains(msg, "50 of 50") || !strings.Contains(msg, "0, 1, 2, 3, 4, ...") {
		t.Errorf("error = %q", msg)
	}
}
