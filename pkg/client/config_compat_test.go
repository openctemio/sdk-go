package client

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

// Configuration files written before the agent -> sensor rename carry
// agent_id; they must keep working.
func TestConfigReadsLegacySensorIDKey(t *testing.T) {
	cases := []struct {
		name, json, yaml string
		want             string
		wantErr          bool
	}{
		{"new key", `{"base_url":"https://x","sensor_id":"s1"}`, "base_url: https://x\nsensor_id: s1\n", "s1", false},
		{"legacy key", `{"base_url":"https://x","agent_id":"a1"}`, "base_url: https://x\nagent_id: a1\n", "a1", false},
		{"both equal", `{"sensor_id":"x","agent_id":"x"}`, "sensor_id: x\nagent_id: x\n", "x", false},
		{"conflict", `{"sensor_id":"x","agent_id":"y"}`, "sensor_id: x\nagent_id: y\n", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var j Config
			err := json.Unmarshal([]byte(tc.json), &j)
			if (err != nil) != tc.wantErr {
				t.Fatalf("json err = %v, wantErr %v", err, tc.wantErr)
			}
			var y Config
			err = yaml.Unmarshal([]byte(tc.yaml), &y)
			if (err != nil) != tc.wantErr {
				t.Fatalf("yaml err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if j.SensorID != tc.want || y.SensorID != tc.want {
				t.Fatalf("json %q yaml %q, want %q", j.SensorID, y.SensorID, tc.want)
			}
			if tc.json[2:10] == "base_url" && (j.BaseURL != "https://x" || y.BaseURL != "https://x") {
				t.Fatalf("other fields lost: json %q yaml %q", j.BaseURL, y.BaseURL)
			}
		})
	}
	out, _ := json.Marshal(&Config{SensorID: "s"})
	var m map[string]any
	_ = json.Unmarshal(out, &m)
	if _, ok := m["agent_id"]; ok {
		t.Fatalf("Config is written with the new key only: %s", out)
	}
}
