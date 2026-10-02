package legacyv1

import (
	"errors"
	"flag"
	"fmt"
)

// SensorRenamedEnv lists the renamed environment variables of a sensor
// binary (the SDK's own, RenamedEnv, included): the names every sensor built
// on pkg/sensorkit reads. ApplyRenamedEnv migrates them at start-up.
var SensorRenamedEnv = []RenamedVar{
	{Old: "AGENT_ID", New: "SENSOR_ID"},
	{Old: "AGENT_NAME", New: "SENSOR_NAME"},
	{Old: "AGENT_ALLOW_PRIVATE_TARGETS", New: "SENSOR_ALLOW_PRIVATE_TARGETS"},
}

// SensorRenamedFlags lists the renamed command-line flags of a sensor binary
// that follows the SDK's naming (-sensor-id). A flag that the binary does not
// define is skipped.
var SensorRenamedFlags = []RenamedVar{
	{Old: "agent-id", New: "sensor-id"},
}

// ApplyRenamedEnv applies every variable of vars that is set only under its
// old name to its new name (with a deprecation warning), so the rest of the
// process reads only new names. It returns an error naming both variables
// for each one set under both names to different values.
func ApplyRenamedEnv(vars []RenamedVar, lookup func(string) (string, bool), setenv func(string, string) error) error {
	var errs []error
	for _, r := range vars {
		v, ok, err := Resolve(r.New, r.Old, "environment", lookup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, hasNew := lookup(r.New); ok && !hasNew {
			if err := setenv(r.New, v); err != nil {
				errs = append(errs, fmt.Errorf("apply %s from deprecated %s: %w", r.New, r.Old, err))
			}
		}
	}
	return errors.Join(errs...)
}

// ApplyRenamedFlags does the same for flags given on the command line of fs:
// an old flag's value is applied to its replacement, with a warning. Flags
// fs does not define are skipped.
func ApplyRenamedFlags(fs *flag.FlagSet, vars []RenamedVar) error {
	given := map[string]string{}
	fs.Visit(func(f *flag.Flag) { given["-"+f.Name] = f.Value.String() })
	lookup := func(name string) (string, bool) { v, ok := given[name]; return v, ok }

	var errs []error
	for _, r := range vars {
		if fs.Lookup(r.New) == nil {
			continue
		}
		v, ok, err := Resolve("-"+r.New, "-"+r.Old, "flag", lookup)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if _, hasNew := given["-"+r.New]; ok && !hasNew {
			if err := fs.Set(r.New, v); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}
