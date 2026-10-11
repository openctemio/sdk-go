package sensorkit

import (
	"fmt"
	"os"
)

// securePrivateDir creates dir (0700) when it is missing and keeps an
// existing one private to the sensor's user: a mode that lets group or
// others in is narrowed to 0700. It returns a warning, for the sensor's
// log, about what it cannot fix (another owner, a refused chmod); the
// stores inside (identity, credentials file, outbox) refuse or narrow their
// own files as before.
//
// The state, outbox and content directories may sit on one data volume
// mounted at /var/lib/openctem; on a bind mount or a Kubernetes volume the
// image's directories are not copied there, so the sensor creates them.
func securePrivateDir(dir string) string {
	if dir == "" {
		return ""
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Sprintf("cannot create %s: %v", dir, err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		return fmt.Sprintf("cannot read %s: %v", dir, err)
	}
	if !fi.IsDir() {
		return dir + " is not a directory"
	}
	if uid, mine := ownedBySensorUser(fi); !mine {
		return fmt.Sprintf("%s is owned by uid %d, not by the sensor's user (uid %d): run chown -R %d %s",
			dir, uid, os.Getuid(), os.Getuid(), dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Sprintf("%s has mode %04o (group or others have access) and cannot be narrowed to 0700: %v",
				dir, fi.Mode().Perm(), err)
		}
	}
	return ""
}
