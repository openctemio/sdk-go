package contentcache

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/localstore"
)

type delayFetcher struct {
	inner *memFetcher
	delay time.Duration
	n     atomic.Int32
}

func (s *delayFetcher) Fetch(ctx context.Context, d string) (io.ReadCloser, error) {
	s.n.Add(1)
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.inner.Fetch(ctx, d)
}

// Concurrent claims of one missing digest share one download and one stored
// copy, and every claimant gets the pack.
func TestInstallConcurrentClaimsDownloadOnce(t *testing.T) {
	f := newFixture(t)
	slow := &delayFetcher{inner: f.fetch, delay: 80 * time.Millisecond}
	f.cache.opts.Fetch = slow
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"dns/s.txt": "www\nmail\n"})
	const n = 12
	var wg sync.WaitGroup
	errs := make(chan error, n)
	dirs := make(chan string, n)
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := f.cache.Install(context.Background(), p)
			if err != nil {
				errs <- err
				return
			}
			dirs <- d
		}()
	}
	wg.Wait()
	close(errs)
	close(dirs)
	for err := range errs {
		t.Fatal(err)
	}
	if got := slow.n.Load(); got != 1 {
		t.Fatalf("%d downloads for one digest, want 1", got)
	}
	seen := map[string]bool{}
	for d := range dirs {
		seen[d] = true
	}
	if len(seen) != 1 || len(f.cache.Held()) != 1 {
		t.Fatalf("copies: paths %v held %v", seen, f.cache.Held())
	}
	entries, _ := os.ReadDir(filepath.Join(f.root, "packs"))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") {
			t.Fatalf("staging left behind: %s", e.Name())
		}
	}
}

// The first caller's deadline does not fail the others waiting on the same
// digest: they download it themselves.
func TestWaiterRetriesWhenTheFirstCallerIsCancelled(t *testing.T) {
	f := newFixture(t)
	slow := &delayFetcher{inner: f.fetch, delay: 150 * time.Millisecond}
	f.cache.opts.Fetch = slow
	p := f.pack(t, ScopePlatform, f.platK, "", map[string]string{"a.txt": "www\n"})
	first, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := f.cache.Install(first, p); done <- err }()
	time.Sleep(30 * time.Millisecond)
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if _, err := f.cache.Install(context.Background(), p); err != nil {
		t.Fatalf("waiter: %v", err)
	}
	if err := <-done; err == nil {
		t.Fatal("canceled install reported success")
	}
	if _, ok := f.cache.Path(p.Digest); !ok {
		t.Fatal("pack not held")
	}
}

// The cache applies the one pack budget (the sensor's pack policy), not a
// separate default.
func TestBudgetFollowsThePackPolicy(t *testing.T) {
	c, err := Open(filepath.Join(t.TempDir(), "c"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.budget(); got != localstore.DefaultPackBudget {
		t.Fatalf("default budget %d, want the janitor's %d", got, localstore.DefaultPackBudget)
	}
	c.SetBudget(123)
	c.SetBudget(0)
	if c.budget() != 123 {
		t.Fatalf("budget %d", c.budget())
	}
}
