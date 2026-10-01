package grpc

import (
	"encoding/json"

	"github.com/openctemio/sdk-go/pkg/sensorproto/legacyv1"
)

// UnmarshalJSON reads Config, accepting the pre-rename key "agent_id" for
// SensorID so configuration files written before the agent -> sensor rename
// keep working (see legacyv1.MergeSensorID).
func (c *Config) UnmarshalJSON(data []byte) error {
	type plain Config
	var v struct {
		plain
		LegacySensorID string `json:"agent_id"`
	}
	v.plain = plain(*c)
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	id, err := legacyv1.MergeSensorID(v.SensorID, v.LegacySensorID)
	if err != nil {
		return err
	}
	*c = Config(v.plain)
	c.SensorID = id
	return nil
}

// UnmarshalYAML does the same for YAML. It uses the function-argument form
// both gopkg.in/yaml.v2 and gopkg.in/yaml.v3 accept, so the SDK does not
// depend on a YAML library.
func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	type plain Config
	p := plain(*c)
	if err := unmarshal(&p); err != nil {
		return err
	}
	var legacy struct {
		LegacySensorID string `yaml:"agent_id"`
	}
	if err := unmarshal(&legacy); err != nil {
		return err
	}
	id, err := legacyv1.MergeSensorID(p.SensorID, legacy.LegacySensorID)
	if err != nil {
		return err
	}
	*c = Config(p)
	c.SensorID = id
	return nil
}
