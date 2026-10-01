package legacyv1

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// RenamedVar is a setting that used the agent vocabulary before the rename.
type RenamedVar struct{ Old, New string }

// RenamedEnv lists the environment variables the SDK itself reads that were
// renamed. Installations set them in .env files, compose files, systemd units
// and Helm values, so the old name keeps working: LookupEnv reads the new
// name first, falls back to the old one with a deprecation warning, and fails
// only when both are set to different values (RFC-023 §9.5, "Upgrade
// migration for existing installations"). A sensor binary passes its own
// renamed variables (AGENT_ID, AGENT_NAME, ...) through the same function.
var RenamedEnv = []RenamedVar{
	{Old: "AGENT_ALLOW_PRIVATE_TARGETS", New: "SENSOR_ALLOW_PRIVATE_TARGETS"},
}

// Credentials file names under ~/.openctem. A sensor that registered before
// the rename has its identity and API key in the old file;
// platform.EnsureRegistered moves it to the new name on first start.
const (
	CredentialsFileName       = "sensor-credentials.json"
	LegacyCredentialsFileName = "agent-credentials.json"
)

// ConflictError reports a renamed setting given under both names with
// different values. It names both settings and never their values, which
// may be secrets.
type ConflictError struct{ Old, New string }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("deprecated configuration: %s and %s are both set to different values; remove %s and keep %s",
		e.Old, e.New, e.Old, e.New)
}

// Warn is called every time a deprecated name is used. The default logs a
// "deprecated configuration" warning through the process's slog logger, once
// per name per process. Replace it to route the warning elsewhere (a sensor
// with its own logger, or a test).
var Warn = func(old, replacement, kind string) {
	if _, loaded := warned.LoadOrStore(kind+"\x00"+old, true); loaded {
		return
	}
	slog.Warn("deprecated configuration", "deprecated", old, "use", replacement, "kind", kind)
}

var warned sync.Map

// Deprecated reports that the setting old was used in place of replacement.
// kind names where it came from ("environment", "flag", "configuration key").
func Deprecated(old, replacement, kind string) { Warn(old, replacement, kind) }

// LookupEnv resolves a renamed environment variable: the new name wins; the
// old one is used, with a warning naming both, only when the new one
// is unset; when both are set to different values it returns a
// *ConflictError rather than silently picking one (a private-targets switch
// that is suddenly on, or off, is a security change). An empty value counts
// as set, as it does for os.LookupEnv.
func LookupEnv(newName, oldName string) (value string, ok bool, err error) {
	return Resolve(newName, oldName, "environment", os.LookupEnv)
}

// Resolve is LookupEnv over any lookup function (command-line flags, a
// configuration file, a test map). kind names the source in warnings.
func Resolve(newName, oldName, kind string, lookup func(string) (string, bool)) (string, bool, error) {
	nv, nok := lookup(newName)
	ov, ook := lookup(oldName)
	switch {
	case nok && ook && nv != ov:
		return "", false, &ConflictError{Old: oldName, New: newName}
	case nok:
		if ook {
			Deprecated(oldName, newName, kind)
		}
		return nv, true, nil
	case ook:
		Deprecated(oldName, newName, kind)
		return ov, true, nil
	}
	return "", false, nil
}

// OldEnvName returns the pre-rename name of an SDK environment variable, or
// "" when it was not renamed.
func OldEnvName(newName string) string {
	for _, v := range RenamedEnv {
		if v.New == newName {
			return v.Old
		}
	}
	return ""
}
