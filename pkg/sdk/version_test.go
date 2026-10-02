package sdk

import (
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func semver(t *testing.T, v string) [3]int {
	t.Helper()
	parts := strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3)
	if len(parts) != 3 {
		t.Fatalf("%q is not X.Y.Z", v)
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			t.Fatalf("%q is not X.Y.Z", v)
		}
		out[i] = n
	}
	return out
}

// Version must not be older than the newest release in CHANGELOG.md, so a
// release cannot ship a stale fallback.
func TestVersionNotBehindChangelog(t *testing.T) {
	data, err := os.ReadFile("../../CHANGELOG.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^## v(\d+\.\d+\.\d+)\b`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("no released version in CHANGELOG.md")
	}
	have, latest := semver(t, Version), semver(t, m[1])
	for i := range 3 {
		if have[i] != latest[i] {
			if have[i] < latest[i] {
				t.Fatalf("sdk.Version %s is older than the latest release v%s in CHANGELOG.md: bump it", Version, m[1])
			}
			return
		}
	}
}
