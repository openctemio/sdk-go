package executor

import (
	"strings"
	"testing"
)

// A confined task's resolv.conf names only the relay and has no search
// list: target names are looked up as written.
func TestTaskResolvConfHasNoSearchList(t *testing.T) {
	var servers []string
	for _, line := range strings.Split(taskResolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		switch f[0] {
		case "search", "domain":
			t.Fatalf("task resolv.conf has a search list: %q", line)
		case "nameserver":
			servers = append(servers, f[1])
		case "options":
		default:
			t.Fatalf("unexpected line %q", line)
		}
	}
	if len(servers) != 1 || servers[0] != "127.0.0.1" {
		t.Fatalf("nameservers %v, want only the relay at 127.0.0.1", servers)
	}
}
