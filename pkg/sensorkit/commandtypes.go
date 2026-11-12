package sensorkit

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

// EnvCommandTypes lists the only command types the sensor accepts
// (comma-separated; Options.CommandTypes). Unset: scan, collect,
// health_check and every handled type.
const EnvCommandTypes = "SENSOR_COMMAND_TYPES"

// resolveCommandTypes is the serve-only list: Options.CommandTypes, else
// SENSOR_COMMAND_TYPES; trimmed, without empty entries and duplicates. nil
// when neither lists a type.
func resolveCommandTypes(opt []string) []string {
	list := opt
	if len(list) == 0 {
		list = ParseToolList(os.Getenv(EnvCommandTypes))
	}
	var out []string
	for _, t := range list {
		if t = strings.TrimSpace(t); t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// checkServeOnly fails when the serve-only list names a command type that
// nothing on this sensor serves: no handler, no middleware, not one of the
// SDK executor's types, and not retest without a tool that retests. Such a
// command would be claimed and then fail.
func (k *Kit) checkServeOnly(scanners []scannerEntry) error {
	if k.s.serveOnly == nil {
		return nil
	}
	served := slices.Clone(defaultCommandTypes)
	for t := range k.handlers {
		served = append(served, t)
	}
	for _, m := range k.middlewares {
		served = append(served, m.types...)
	}
	if newRetestExecutor(scanners, k.retests, k.retestTemplates, nil, nil, nil) != nil {
		served = append(served, RetestCommandType)
	}
	var missing []string
	for _, t := range k.s.serveOnly {
		if !slices.Contains(served, t) {
			missing = append(missing, t)
		}
	}
	if len(missing) > 0 {
		return usageError(fmt.Errorf("%s lists %s, which no handler serves: register one with HandleCommand "+
			"(the SDK's executor serves %s)", EnvCommandTypes, strings.Join(missing, ", "), strings.Join(defaultCommandTypes, ", ")))
	}
	return nil
}
