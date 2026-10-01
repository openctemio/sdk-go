package legacyv1

import (
	"errors"
	"strings"
	"sync"
	"testing"
)

// captureWarn records Warn calls and resets the once-per-process memory.
func captureWarn(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := Warn
	Warn = func(old, replacement, kind string) { got = append(got, kind+":"+old+"->"+replacement) }
	warned = sync.Map{}
	t.Cleanup(func() { Warn = prev; warned = sync.Map{} })
	return &got
}

func TestLookupEnv(t *testing.T) {
	const newName, oldName = "SENSOR_TEST_X", "AGENT_TEST_X"
	tests := []struct {
		name      string
		env       map[string]string
		wantVal   string
		wantOK    bool
		wantWarn  bool
		wantError bool
	}{
		{name: "neither set", env: nil},
		{name: "new only", env: map[string]string{newName: "1"}, wantVal: "1", wantOK: true},
		{name: "old only is mapped with a warning", env: map[string]string{oldName: "1"}, wantVal: "1", wantOK: true, wantWarn: true},
		{name: "both equal: new used, old reported", env: map[string]string{newName: "1", oldName: "1"}, wantVal: "1", wantOK: true, wantWarn: true},
		{name: "both different is refused", env: map[string]string{newName: "1", oldName: "0"}, wantError: true},
		{name: "empty old value still counts as set", env: map[string]string{oldName: ""}, wantVal: "", wantOK: true, wantWarn: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warns := captureWarn(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			val, ok, err := LookupEnv(newName, oldName)
			if tt.wantError {
				var ce *ConflictError
				if !errors.As(err, &ce) {
					t.Fatalf("err = %v, want *ConflictError", err)
				}
				msg := err.Error()
				if !strings.Contains(msg, oldName) || !strings.Contains(msg, newName) {
					t.Fatalf("conflict error %q must name both variables", msg)
				}
				if strings.Contains(msg, "=1") || strings.Contains(msg, "=0") {
					t.Fatalf("conflict error %q must not print values", msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if val != tt.wantVal || ok != tt.wantOK {
				t.Fatalf("got (%q, %v), want (%q, %v)", val, ok, tt.wantVal, tt.wantOK)
			}
			if gotWarn := len(*warns) > 0; gotWarn != tt.wantWarn {
				t.Fatalf("warnings = %v, want warning: %v", *warns, tt.wantWarn)
			}
			if tt.wantWarn && (*warns)[0] != "environment:"+oldName+"->"+newName {
				t.Fatalf("warning = %q, must name both variables", (*warns)[0])
			}
		})
	}
}

func TestWarnOnce(t *testing.T) {
	warns := captureWarn(t)
	t.Setenv("AGENT_TEST_Y", "a")
	for range 3 {
		if _, _, err := LookupEnv("SENSOR_TEST_Y", "AGENT_TEST_Y"); err != nil {
			t.Fatal(err)
		}
	}
	if len(*warns) != 1 {
		t.Fatalf("warned %d times, want once", len(*warns))
	}
}

func TestRenamedEnvTable(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range RenamedEnv {
		if !strings.HasPrefix(v.Old, "AGENT_") || v.New != "SENSOR_"+strings.TrimPrefix(v.Old, "AGENT_") {
			t.Errorf("%s -> %s is not the exact AGENT_ -> SENSOR_ mapping", v.Old, v.New)
		}
		if seen[v.Old] {
			t.Errorf("%s listed twice", v.Old)
		}
		seen[v.Old] = true
		if OldEnvName(v.New) != v.Old {
			t.Errorf("OldEnvName(%s) = %q", v.New, OldEnvName(v.New))
		}
	}
	if OldEnvName("API_KEY") != "" {
		t.Error("API_KEY was not renamed")
	}
}

func TestMergeSensorID(t *testing.T) {
	warns := captureWarn(t)
	if id, err := MergeSensorID("s1", ""); err != nil || id != "s1" {
		t.Fatalf("current only: %q %v", id, err)
	}
	if len(*warns) != 0 {
		t.Fatalf("no warning expected, got %v", *warns)
	}
	if id, err := MergeSensorID("", "a1"); err != nil || id != "a1" {
		t.Fatalf("legacy only: %q %v", id, err)
	}
	if len(*warns) != 1 {
		t.Fatalf("legacy key must warn, got %v", *warns)
	}
	if id, err := MergeSensorID("x", "x"); err != nil || id != "x" {
		t.Fatalf("equal: %q %v", id, err)
	}
	if _, err := MergeSensorID("x", "y"); err == nil || !strings.Contains(err.Error(), "agent_id") || !strings.Contains(err.Error(), "sensor_id") {
		t.Fatalf("conflict must be an error naming both keys, got %v", err)
	}
}
