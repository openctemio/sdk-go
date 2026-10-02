package legacyv1

import (
	"flag"
	"strings"
	"testing"
)

type fakeEnv map[string]string

func (e fakeEnv) lookup(k string) (string, bool) { v, ok := e[k]; return v, ok }
func (e fakeEnv) set(k, v string) error          { e[k] = v; return nil }

// One case per renamed variable: the old name alone is applied to the new
// one, with a warning naming both; unrenamed settings are untouched.
func TestApplyRenamedEnvMapsEachOldVariable(t *testing.T) {
	for _, r := range SensorRenamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			warns := captureWarn(t)
			env := fakeEnv{r.Old: "value-1", "API_URL": "https://api", "API_KEY": "k", "BOOTSTRAP_TOKEN": "b"}
			if err := ApplyRenamedEnv(SensorRenamedEnv, env.lookup, env.set); err != nil {
				t.Fatal(err)
			}
			if env[r.New] != "value-1" {
				t.Fatalf("%s = %q, want the value of %s", r.New, env[r.New], r.Old)
			}
			if len(*warns) != 1 || !strings.Contains((*warns)[0], r.Old) || !strings.Contains((*warns)[0], r.New) {
				t.Fatalf("warnings = %v, want one naming %s and %s", *warns, r.Old, r.New)
			}
			if env["API_URL"] != "https://api" || env["API_KEY"] != "k" || env["BOOTSTRAP_TOKEN"] != "b" {
				t.Fatalf("API_URL / API_KEY / BOOTSTRAP_TOKEN changed: %v", env)
			}
		})
	}
}

func TestApplyRenamedEnvNewNameWinsWhenEqual(t *testing.T) {
	for _, r := range SensorRenamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			warns := captureWarn(t)
			env := fakeEnv{r.Old: "x", r.New: "x"}
			if err := ApplyRenamedEnv(SensorRenamedEnv, env.lookup, env.set); err != nil {
				t.Fatal(err)
			}
			if env[r.New] != "x" || len(*warns) != 1 {
				t.Fatalf("env %v warnings %v", env, *warns)
			}
		})
	}
}

// Old and new set to different values: refused, naming both, never values.
func TestApplyRenamedEnvRefusesConflicts(t *testing.T) {
	for _, r := range SensorRenamedEnv {
		t.Run(r.Old, func(t *testing.T) {
			captureWarn(t)
			env := fakeEnv{r.Old: "old-secret", r.New: "new-secret"}
			err := ApplyRenamedEnv(SensorRenamedEnv, env.lookup, env.set)
			if err == nil {
				t.Fatal("conflict must be refused")
			}
			msg := err.Error()
			if !strings.Contains(msg, r.Old) || !strings.Contains(msg, r.New) {
				t.Fatalf("error %q must name %s and %s", msg, r.Old, r.New)
			}
			if strings.Contains(msg, "secret") {
				t.Fatalf("error %q must not print values", msg)
			}
			if env[r.New] != "new-secret" {
				t.Fatal("a conflict must not overwrite the new value")
			}
		})
	}
}

func TestSensorRenamedEnvTable(t *testing.T) {
	want := map[string]string{
		"AGENT_ID":                    "SENSOR_ID",
		"AGENT_NAME":                  "SENSOR_NAME",
		"AGENT_ALLOW_PRIVATE_TARGETS": "SENSOR_ALLOW_PRIVATE_TARGETS",
	}
	if len(SensorRenamedEnv) != len(want) {
		t.Fatalf("SensorRenamedEnv = %v", SensorRenamedEnv)
	}
	for _, r := range SensorRenamedEnv {
		if want[r.Old] != r.New {
			t.Errorf("%s -> %s, want %s", r.Old, r.New, want[r.Old])
		}
	}
	// The SDK's own renamed variables are a subset.
	for _, r := range RenamedEnv {
		if want[r.Old] != r.New {
			t.Errorf("RenamedEnv %s -> %s missing from SensorRenamedEnv", r.Old, r.New)
		}
	}
}

func newFlags() (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("sensor", flag.ContinueOnError)
	id := fs.String("sensor-id", "", "")
	_ = fs.String("agent-id", "", "")
	return fs, id
}

func TestApplyRenamedFlags(t *testing.T) {
	t.Run("old flag is applied with a warning", func(t *testing.T) {
		warns := captureWarn(t)
		fs, id := newFlags()
		if err := fs.Parse([]string{"--agent-id", "s-1"}); err != nil {
			t.Fatal(err)
		}
		if err := ApplyRenamedFlags(fs, SensorRenamedFlags); err != nil {
			t.Fatal(err)
		}
		if *id != "s-1" {
			t.Fatalf("-sensor-id = %q", *id)
		}
		if len(*warns) != 1 || !strings.Contains((*warns)[0], "-agent-id") {
			t.Fatalf("warnings = %v", *warns)
		}
	})
	t.Run("new flag alone", func(t *testing.T) {
		warns := captureWarn(t)
		fs, id := newFlags()
		_ = fs.Parse([]string{"-sensor-id", "s-2"})
		if err := ApplyRenamedFlags(fs, SensorRenamedFlags); err != nil || *id != "s-2" || len(*warns) != 0 {
			t.Fatalf("id %q err %v warnings %v", *id, err, *warns)
		}
	})
	t.Run("conflict is refused", func(t *testing.T) {
		captureWarn(t)
		fs, _ := newFlags()
		_ = fs.Parse([]string{"-sensor-id", "a", "-agent-id", "b"})
		err := ApplyRenamedFlags(fs, SensorRenamedFlags)
		if err == nil || !strings.Contains(err.Error(), "-agent-id") || !strings.Contains(err.Error(), "-sensor-id") {
			t.Fatalf("err = %v, want a conflict naming both flags", err)
		}
	})
	t.Run("a binary without the flag is skipped", func(t *testing.T) {
		captureWarn(t)
		fs := flag.NewFlagSet("other", flag.ContinueOnError)
		if err := ApplyRenamedFlags(fs, SensorRenamedFlags); err != nil {
			t.Fatal(err)
		}
	})
}
