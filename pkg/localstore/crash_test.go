//go:build unix

package localstore

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestMain doubles as the writer process the crash test kills.
func TestMain(m *testing.M) {
	if dir := os.Getenv("LOCALSTORE_CRASH_WRITER"); dir != "" {
		crashWriter(dir)
		return
	}
	os.Exit(m.Run())
}

// crashWriter writes records forever and prints the name of each one after
// Put returned (the acknowledgement the parent checks after kill -9).
func crashWriter(dir string) {
	s, err := Open(Options{Dir: dir, Logf: quiet})
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	kv, err := s.KV(SensorTenant, "journal")
	if err != nil {
		fmt.Println("ERR", err)
		os.Exit(2)
	}
	w := bufio.NewWriter(os.Stdout)
	for i := 0; ; i++ {
		name := fmt.Sprintf("r%d", i%50)
		val := fmt.Sprintf("v%d", i)
		if err := kv.Put(name, []byte(val)); err != nil {
			fmt.Println("ERR", err)
			os.Exit(2)
		}
		fmt.Fprintf(w, "%s=%s\n", name, val)
		_ = w.Flush()
	}
}

// TestKillDashNineNeverCorrupts kills a writer at random points many times
// and checks that the store opens, nothing is quarantined, and every record
// holds the last acknowledged value or a later one being written.
func TestKillDashNineNeverCorrupts(t *testing.T) {
	if testing.Short() {
		t.Skip("crash loop")
	}
	dir := t.TempDir()
	rounds := 25
	for r := range rounds {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "LOCALSTORE_CRASH_WRITER="+dir)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		acked := map[string]int{}
		sc := bufio.NewScanner(out)
		deadline := time.Now().Add(time.Duration(20+r*7%60) * time.Millisecond)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "ERR") {
				t.Fatalf("writer: %s", line)
			}
			name, val, _ := strings.Cut(line, "=")
			var n int
			_, _ = fmt.Sscanf(val, "v%d", &n)
			acked[name] = n
			if time.Now().After(deadline) {
				break
			}
		}
		_ = cmd.Process.Signal(syscall.SIGKILL)
		_ = cmd.Wait()

		s, err := Open(Options{Dir: dir, Logf: quiet})
		if err != nil {
			t.Fatalf("round %d: reopen after kill -9: %v", r, err)
		}
		kv, err := s.KV(SensorTenant, "journal")
		if err != nil {
			t.Fatalf("round %d: %v", r, err)
		}
		for name, want := range acked {
			got, err := kv.Get(name)
			if err != nil {
				t.Fatalf("round %d: acknowledged %s lost: %v", r, name, err)
			}
			var n int
			_, _ = fmt.Sscanf(string(got), "v%d", &n)
			if n < want {
				t.Fatalf("round %d: %s = v%d, older than acknowledged v%d", r, name, n, want)
			}
		}
		if st := s.Stats(); st.Tampered != 0 {
			t.Fatalf("round %d: records quarantined after kill -9: %+v", r, st)
		}
		if err := s.Close(); err != nil && !errors.Is(err, ErrClosed) {
			t.Fatal(err)
		}
	}
}
