package sensorkit

import (
	"os"
	"path/filepath"
	"testing"

	settingsreg "github.com/openctemio/sdk-go/pkg/sensorkit/settings"
)

const settingsDocHeader = "# Sensor settings (SDK)\n\n" +
	"Generated from the settings registry (`sensorkit.RegisterSDKSettings`); do not edit.\n" +
	"Regenerate with `UPDATE_SETTINGS_DOC=1 go test ./pkg/sensorkit -run TestSettingsDocUpToDate`.\n" +
	"A sensor declares its own settings in the same registry; the platform's\n" +
	"Setup & health checklist shows each one's presence, never its value.\n\n"

// docs/SETTINGS.md is generated from the registry and must not drift.
func TestSettingsDocUpToDate(t *testing.T) {
	r := settingsreg.New()
	RegisterSDKSettings(r)
	want := settingsDocHeader + r.Markdown()
	path := filepath.Join("..", "..", "docs", "SETTINGS.md")
	if os.Getenv("UPDATE_SETTINGS_DOC") == "1" {
		if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatal("docs/SETTINGS.md is stale: run UPDATE_SETTINGS_DOC=1 go test ./pkg/sensorkit -run TestSettingsDocUpToDate")
	}
}
