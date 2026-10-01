package legacyv1

import "fmt"

// ConfigKeySensorID is the configuration-file key (YAML and JSON) of the
// sensor id in SDK configuration structs from before the rename; the key is
// now "sensor_id".
const ConfigKeySensorID = "agent_id"

// MergeSensorID resolves a sensor id read from a configuration file that may
// carry the current key ("sensor_id", current) and the pre-rename one
// ("agent_id", legacy). The current key wins; the legacy one is used, with a
// warning, only when the current one is empty; both set to
// different values is an error naming both keys.
func MergeSensorID(current, legacy string) (string, error) {
	switch {
	case legacy == "":
		return current, nil
	case current != "" && current != legacy:
		return "", fmt.Errorf("deprecated configuration: %q and %q are both set to different values; keep only %q",
			"sensor_id", ConfigKeySensorID, "sensor_id")
	}
	Deprecated(ConfigKeySensorID, "sensor_id", "configuration key")
	return legacy, nil
}
