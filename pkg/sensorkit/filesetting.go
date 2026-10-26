package sensorkit

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Environment variables that name a file holding the value of a setting, so
// the value itself never sits in the process environment (visible to
// `docker inspect`, /proc/<pid>/environ and child processes). Setting both
// the variable and its _FILE form stops the sensor.
const (
	EnvInstanceEnrollmentTokenFile = EnvInstanceEnrollmentToken + "_FILE"
	EnvEnrollmentTokenFile         = EnvEnrollmentToken + "_FILE"
	EnvJobSigningKeysFile          = EnvJobSigningKeys + "_FILE"
	EnvJobSigningRootFile          = EnvJobSigningRoot + "_FILE"
)

// maxSettingFile bounds a setting file; every value read this way is far
// smaller (a token, a key id, a few keys).
const maxSettingFile = 64 << 10

// settingValue returns the value of a setting that has a _FILE form: opt (a
// programmatic option) or the environment variable name, else the trimmed
// content of the file named by name+"_FILE". Both given is an error. The
// error never carries the value.
func settingValue(opt, name string) (value string, fromFile bool, err error) {
	direct := strings.TrimSpace(envOr(opt, name))
	fileVar := name + "_FILE"
	path := strings.TrimSpace(os.Getenv(fileVar))
	switch {
	case path == "":
		return direct, false, nil
	case direct != "":
		return "", false, usageError(fmt.Errorf("set %s or %s, not both", name, fileVar))
	}
	v, err := readSettingFile(path)
	if err != nil {
		return "", false, usageError(fmt.Errorf("%s: %w", fileVar, err))
	}
	return v, true, nil
}

// readSettingFile reads a setting file for settingValue. It refuses a file
// that group or others can write (they could swap the value), a symlink
// that leads outside the directory it sits in (a container secret's
// ..data link stays inside), anything but a regular file, an empty file
// and one over maxSettingFile.
func readSettingFile(path string) (string, error) {
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, unwrapPath(err))
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, unwrapPath(err))
	}
	if rel, err := filepath.Rel(dir, real); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("%s is a symbolic link that leads outside its directory", path)
	}
	f, err := os.Open(real)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, unwrapPath(err))
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, unwrapPath(err))
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o022 != 0 {
		return "", fmt.Errorf("%s is writable by group or others (mode %04o); make it at most 0644 and owned by the account that installs it", path, fi.Mode().Perm())
	}
	if fi.Size() > maxSettingFile {
		return "", fmt.Errorf("%s is larger than %d bytes", path, maxSettingFile)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxSettingFile+1))
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", path, unwrapPath(err))
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return v, nil
}

// unwrapPath drops the path an *os.PathError repeats.
func unwrapPath(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
