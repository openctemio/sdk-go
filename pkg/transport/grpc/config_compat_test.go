package grpc

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigReadsLegacySensorIDKey(t *testing.T) {
	var j Config
	if err := json.Unmarshal([]byte(`{"address":"h:1","agent_id":"a1"}`), &j); err != nil || j.SensorID != "a1" {
		t.Fatalf("json legacy key: %+v %v", j, err)
	}
	var y Config
	if err := yaml.Unmarshal([]byte("sensor_id: s1\n"), &y); err != nil || y.SensorID != "s1" {
		t.Fatalf("yaml new key: %+v %v", y, err)
	}
	if err := yaml.Unmarshal([]byte("sensor_id: s1\nagent_id: a1\n"), &y); err == nil {
		t.Fatal("conflicting keys must be refused")
	}
}
