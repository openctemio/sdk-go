package gitleaks

import (
	"context"
	"testing"

	"github.com/openctemio/sdk-go/pkg/core"
	"github.com/openctemio/sdk-go/pkg/ctis"
)

func TestParser_CreateAssetFromOptions(t *testing.T) {
	parser := &Parser{}

	tests := []struct {
		name          string
		opts          *core.ParseOptions
		wantAsset     bool
		wantAssetName string
		wantAssetType ctis.AssetType
	}{
		{
			name:      "nil options returns nil asset",
			opts:      nil,
			wantAsset: false,
		},
		{
			name:      "empty options returns nil asset",
			opts:      &core.ParseOptions{},
			wantAsset: false,
		},
		{
			name: "AssetValue creates asset",
			opts: &core.ParseOptions{
				AssetValue: "github.com/org/repo",
				AssetType:  ctis.AssetTypeRepository,
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "BranchInfo creates asset when AssetValue is empty",
			opts: &core.ParseOptions{
				BranchInfo: &ctis.BranchInfo{
					RepositoryURL:   "github.com/org/repo",
					Name:            "main",
					CommitSHA:       "abc123",
					IsDefaultBranch: true,
				},
			},
			wantAsset:     true,
			wantAssetName: "github.com/org/repo",
			wantAssetType: ctis.AssetTypeRepository,
		},
		{
			name: "AssetValue takes priority over BranchInfo",
			opts: &core.ParseOptions{
				AssetValue: "explicit-asset",
				AssetType:  ctis.AssetTypeContainer,
				BranchInfo: &ctis.BranchInfo{
					RepositoryURL: "github.com/org/repo",
				},
			},
			wantAsset:     true,
			wantAssetName: "explicit-asset",
			wantAssetType: ctis.AssetTypeContainer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset := parser.createAssetFromOptions(tt.opts)

			if tt.wantAsset {
				if asset == nil {
					t.Fatalf("expected asset, got nil")
				}
				if asset.Name != tt.wantAssetName {
					t.Errorf("asset name = %q, want %q", asset.Name, tt.wantAssetName)
				}
				if asset.Type != tt.wantAssetType {
					t.Errorf("asset type = %q, want %q", asset.Type, tt.wantAssetType)
				}
			} else {
				if asset != nil {
					t.Errorf("expected nil asset, got %+v", asset)
				}
			}
		})
	}
}

func TestParser_ParseWithAssetFromBranchInfo(t *testing.T) {
	parser := &Parser{}

	// Empty gitleaks output (no findings)
	data := []byte(`[]`)

	opts := &core.ParseOptions{
		BranchInfo: &ctis.BranchInfo{
			RepositoryURL:   "github.com/myorg/myrepo",
			Name:            "feature-branch",
			CommitSHA:       "abc123def456",
			IsDefaultBranch: false,
		},
	}

	report, err := parser.Parse(context.Background(), data, opts)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(report.Assets) != 1 {
		t.Fatalf("expected 1 asset, got %d", len(report.Assets))
	}

	asset := report.Assets[0]
	if asset.Value != "github.com/myorg/myrepo" {
		t.Errorf("asset value = %q, want %q", asset.Value, "github.com/myorg/myrepo")
	}
	if asset.Type != ctis.AssetTypeRepository {
		t.Errorf("asset type = %q, want %q", asset.Type, ctis.AssetTypeRepository)
	}

	// Verify properties
	if asset.Properties["source"] != "branch_info" {
		t.Errorf("asset source = %v, want branch_info", asset.Properties["source"])
	}
	if asset.Properties["branch"] != "feature-branch" {
		t.Errorf("asset branch = %v, want feature-branch", asset.Properties["branch"])
	}
	if asset.Properties["commit_sha"] != "abc123def456" {
		t.Errorf("asset commit_sha = %v, want abc123def456", asset.Properties["commit_sha"])
	}
}
