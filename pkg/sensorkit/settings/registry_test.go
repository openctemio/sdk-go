package settings

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testRegistry() *Registry {
	r := New()
	r.Register(
		Setting{Name: "API_KEY", Type: String, Required: true, Secret: true},
		Setting{Name: "SENSOR_MAX_JOBS", Type: Int, Validate: func(v string) error {
			if v == "0" {
				return errors.New("1-100")
			}
			return nil
		}},
		Setting{Name: "SENSOR_PROTOCOL", Type: Enum, Enum: []string{"auto", "v1", "v2"}, Default: "auto"},
		Setting{Name: "SENSOR_STATE_DIR", Type: Path},
	)
	return r
}

func env(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestStates_PresenceSourceValidityNoValues(t *testing.T) {
	r := testRegistry()
	r.MarkOption("SENSOR_STATE_DIR")
	sts := r.States(env(map[string]string{"API_KEY": "CANARY-KEY", "SENSOR_MAX_JOBS": "0", "SENSOR_PROTOCOL": "v9"}))
	raw, _ := json.Marshal(sts)
	if strings.Contains(string(raw), "CANARY-KEY") || strings.Contains(string(raw), "v9") {
		t.Fatalf("a value leaked: %s", raw)
	}
	want := map[string]State{
		"API_KEY":          {Name: "API_KEY", Set: true, Source: SourceEnv, Secret: true, Valid: true},
		"SENSOR_MAX_JOBS":  {Name: "SENSOR_MAX_JOBS", Set: true, Source: SourceEnv, Valid: false},
		"SENSOR_PROTOCOL":  {Name: "SENSOR_PROTOCOL", Set: true, Source: SourceEnv, Valid: false},
		"SENSOR_STATE_DIR": {Name: "SENSOR_STATE_DIR", Set: true, Source: SourceOption, Valid: true},
	}
	for _, s := range sts {
		if s != want[s.Name] {
			t.Errorf("%s: %+v, want %+v", s.Name, s, want[s.Name])
		}
	}
	missing := r.States(env(nil))
	if missing[0].Valid || missing[0].Source != SourceUnset {
		t.Fatalf("a required unset setting is not valid: %+v", missing[0])
	}
	if missing[2].Source != SourceDefault {
		t.Fatalf("default source: %+v", missing[2])
	}
}

func TestUnknown_DidYouMean(t *testing.T) {
	r := testRegistry()
	got := r.Unknown([]string{"SENSOR_MAX_JOB=4", "SENSOR_MAX_JOBS=4", "PATH=/bin", "SENSOR_WHATEVER=1", "OPENCTEM_SDK_X=1"},
		"SENSOR_", "OPENCTEM_SDK_")
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[1].Name != "SENSOR_MAX_JOB" || got[1].DidYouMean != "SENSOR_MAX_JOBS" {
		t.Fatalf("%+v", got[1])
	}
	if got[2].DidYouMean != "" {
		t.Fatalf("no suggestion for a far name: %+v", got[2])
	}
}

func TestRegister_DuplicatePanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	r := testRegistry()
	r.Register(Setting{Name: "API_KEY"})
}

func TestSecretValuesAndDocs(t *testing.T) {
	r := testRegistry()
	if v := r.SecretValues(env(map[string]string{"API_KEY": "k1", "SENSOR_MAX_JOBS": "4"})); len(v) != 1 || v[0] != "k1" {
		t.Fatalf("%v", v)
	}
	md := r.Markdown()
	if !strings.Contains(md, "[`API_KEY`](https://docs.openctem.io/sensors/settings/#API_KEY)") {
		t.Fatal(md)
	}
	if Closest("max_job", []string{"max_jobs", "tools"}) != "max_jobs" || Distance("kitten", "sitting") != 3 {
		t.Fatal("distance")
	}
}
