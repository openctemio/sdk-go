package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openctemio/sdk-go/pkg/transfer"
)

const feed = "testfeed"

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

type rec struct {
	ID string `json:"id"`
	V  int    `json:"v"`
}

// dataset returns n records with versions from vers (default 1).
func dataset(n int, vers map[string]int) map[string]int {
	out := map[string]int{}
	for i := range n {
		id := fmt.Sprintf("r%06d", i)
		out[id] = 1
		if v, ok := vers[id]; ok {
			out[id] = v
		}
	}
	return out
}

func sortedIDs(m map[string]int) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func writeKind(t *testing.T, dir, kind string, seq, base uint64, data map[string]int, ids []string, signer Signer) (*Manifest, FileRef) {
	t.Helper()
	w, err := NewWriter(dir, WriterOptions{Feed: feed, Sequence: seq, Kind: kind, BaseSequence: base, TargetRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Stream("records"); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		b, _ := json.Marshal(rec{ID: id, V: data[id]})
		if err := w.Add(id, b); err != nil {
			t.Fatal(err)
		}
	}
	created := t0.Add(time.Duration(seq) * time.Hour)
	m, ref, err := w.Finish(json.RawMessage(`{"source":"test"}`), created, created.Add(7*24*time.Hour), signer)
	if err != nil {
		t.Fatal(err)
	}
	return m, ref
}

// release writes sequence seq (snapshot of data, plus a delta when prev is
// given) into its own directory and returns it.
func release(t *testing.T, root string, seq uint64, data, prev map[string]int, signer Signer) (string, *Manifest) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprintf("seq%d", seq))
	snap, sref := writeKind(t, dir, KindSnapshot, seq, 0, data, sortedIDs(data), signer)
	p := Pointer{Feed: feed, Sequence: seq, Snapshot: sref, CreatedAt: snap.CreatedAt, ExpiresAt: snap.ExpiresAt}
	if prev != nil {
		var changed []string
		for _, id := range sortedIDs(data) {
			if prev[id] != data[id] {
				changed = append(changed, id)
			}
		}
		_, dref := writeKind(t, dir, KindDelta, seq, seq-1, data, changed, signer)
		p.Delta, p.BaseSequence = &dref, seq-1
	}
	if err := WritePointer(dir, p, signer); err != nil {
		t.Fatal(err)
	}
	return dir, snap
}

// origin serves a directory with optional faults and counts chunk requests.
type origin struct {
	mu     sync.Mutex
	dir    string
	fail   bool
	chunks atomic.Int32
}

func (o *origin) set(dir string) { o.mu.Lock(); o.dir = dir; o.mu.Unlock() }

func (o *origin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	dir, fail := o.dir, o.fail
	o.mu.Unlock()
	name := filepath.Base(r.URL.Path)
	if strings.HasPrefix(name, "sha256-") {
		o.chunks.Add(1)
	}
	if fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	http.ServeFile(w, r, filepath.Join(dir, name))
}

// memApplier stores records in memory, keyed by id with their sequence.
type memApplier struct {
	mu        sync.Mutex
	recs      map[string]rec
	seqOf     map[string]uint64
	applied   []int // chunk indexes, in order
	failAt    int   // chunk index that fails once (-1: none)
	completes int
	seenSnap  map[string]bool
}

func newApplier() *memApplier {
	return &memApplier{recs: map[string]rec{}, seqOf: map[string]uint64{}, failAt: -1}
}

func (a *memApplier) ApplyChunk(_ context.Context, c *Chunk, _ State) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if c.Index == a.failAt {
		a.failAt = -1
		return errors.New("simulated crash")
	}
	if c.Index == 0 {
		a.seenSnap = map[string]bool{}
	}
	staged := map[string]rec{}
	err := c.Records(func(line []byte) error {
		var r rec
		if err := json.Unmarshal(line, &r); err != nil {
			return err
		}
		staged[r.ID] = r
		return nil
	})
	if err != nil {
		return err // nothing committed
	}
	for id, r := range staged {
		if a.seqOf[id] > c.Manifest.Sequence {
			continue // never replace a newer record
		}
		a.recs[id], a.seqOf[id] = r, c.Manifest.Sequence
		if a.seenSnap != nil {
			a.seenSnap[id] = true
		}
	}
	a.applied = append(a.applied, c.Index)
	return nil
}

func (a *memApplier) Complete(_ context.Context, m *Manifest, _ State) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.completes++
	if m.Kind == KindSnapshot {
		for id, s := range a.seqOf {
			if s < m.Sequence {
				delete(a.recs, id)
				delete(a.seqOf, id)
			}
		}
	}
	return nil
}

type env struct {
	t       *testing.T
	root    string
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	primary *origin
	srv     *httptest.Server
	cp      FileCheckpoint
	cache   string
	now     time.Time
}

func newEnv(t *testing.T) *env {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	e := &env{t: t, root: t.TempDir(), priv: priv, pub: pub, primary: &origin{}, cache: t.TempDir(), now: t0.Add(24 * time.Hour)}
	e.srv = httptest.NewServer(e.primary)
	t.Cleanup(e.srv.Close)
	e.cp = FileCheckpoint{Path: filepath.Join(t.TempDir(), "state", "testfeed.json")}
	return e
}

func (e *env) signer() Signer { return Ed25519Signer{Key: e.priv} }

func (e *env) consumer(a Applier, extra ...transfer.Origin) (*Consumer, *transfer.Fetcher) {
	e.t.Helper()
	origins := append([]transfer.Origin{{URL: e.srv.URL}}, extra...)
	f, err := transfer.New(transfer.Config{Origins: origins, Client: e.srv.Client(), CacheDir: e.cache,
		Policy: transfer.Policy{MaxAttempts: 2, BackoffBase: time.Millisecond, BackoffMax: time.Millisecond}})
	if err != nil {
		e.t.Fatal(err)
	}
	c, err := NewConsumer(Config{Feed: feed, Fetcher: f, Verifier: NewEd25519Verifier(e.pub), Checkpoint: e.cp,
		Applier: a, Now: func() time.Time { return e.now }})
	if err != nil {
		e.t.Fatal(err)
	}
	return c, f
}

func (e *env) state() State {
	s, err := e.cp.Load(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

func TestSnapshotThenDeltaThenUpToDate(t *testing.T) {
	e := newEnv(t)
	d1 := dataset(3000, nil)
	dir1, m1 := release(t, e.root, 1, d1, nil, e.signer())
	if n := len(m1.Chunks()); n < 10 {
		t.Fatalf("only %d chunks: chunking did not split", n)
	}
	e.primary.set(dir1)
	a := newApplier()
	c, _ := e.consumer(a)
	res, err := c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindSnapshot || res.Records != 3000 || len(a.recs) != 3000 || a.completes != 1 {
		t.Fatalf("res %+v recs %d", res, len(a.recs))
	}
	if s := e.state(); s.Applied != 1 || s.InProgress != 0 {
		t.Fatalf("state %+v", s)
	}

	d2 := dataset(3000, map[string]int{"r000010": 2, "r001500": 2, "r002999": 2})
	dir2, _ := release(t, e.root, 2, d2, d1, e.signer())
	e.primary.set(dir2)
	before := e.primary.chunks.Load()
	res, err = c.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Kind != KindDelta || res.Records != 3 || a.recs["r001500"].V != 2 || a.recs["r000011"].V != 1 || len(a.recs) != 3000 {
		t.Fatalf("delta res %+v", res)
	}
	if got := e.primary.chunks.Load() - before; got != int32(res.ChunksApplied) {
		t.Fatalf("delta fetched %d chunks, applied %d", got, res.ChunksApplied)
	}
	res, err = c.Run(context.Background())
	if err != nil || !res.UpToDate {
		t.Fatalf("third run %+v %v", res, err)
	}
}

func TestUnchangedChunksAreReusedAcrossReleases(t *testing.T) {
	e := newEnv(t)
	d1 := dataset(3000, nil)
	dir1, m1 := release(t, e.root, 1, d1, nil, e.signer())
	d2 := dataset(3000, map[string]int{"r001234": 9})
	_, m2 := release(t, e.root, 2, d2, d1, e.signer())
	old := map[string]bool{}
	for _, c := range m1.Chunks() {
		old[c.Ref.SHA256] = true
	}
	shared := 0
	for _, c := range m2.Chunks() {
		if old[c.Ref.SHA256] {
			shared++
		}
	}
	if shared != len(m2.Chunks())-1 {
		t.Fatalf("%d of %d chunks shared, want all but one", shared, len(m2.Chunks()))
	}
	// A consumer that re-takes the snapshot downloads only the changed chunk.
	e.primary.set(dir1)
	a := newApplier()
	c, _ := e.consumer(a)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	e.primary.set(filepath.Join(e.root, "seq2"))
	if err := e.cp.Save(context.Background(), State{Feed: feed, Applied: 0}); err != nil { // force a snapshot
		t.Fatal(err)
	}
	before := e.primary.chunks.Load()
	res, err := c.Run(context.Background())
	if err != nil || res.Kind != KindSnapshot {
		t.Fatalf("%+v %v", res, err)
	}
	if got := e.primary.chunks.Load() - before; got != 1 {
		t.Fatalf("re-snapshot downloaded %d chunks, want 1", got)
	}
}

func TestCrashBetweenChunksResumes(t *testing.T) {
	e := newEnv(t)
	dir, m := release(t, e.root, 1, dataset(3000, nil), nil, e.signer())
	e.primary.set(dir)
	a := newApplier()
	a.failAt = 4
	c, _ := e.consumer(a)
	if _, err := c.Run(context.Background()); err == nil {
		t.Fatal("crash not reported")
	}
	s := e.state()
	if s.Applied != 0 || s.InProgress != 1 || s.NextChunk != 4 || a.completes != 0 {
		t.Fatalf("state after crash %+v completes %d", s, a.completes)
	}
	// A new process resumes at chunk 4.
	c2, _ := e.consumer(a)
	res, err := c2.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.Resumed || res.ChunksApplied != len(m.Chunks())-4 || a.applied[4] != 4 || len(a.recs) != 3000 {
		t.Fatalf("res %+v applied %v", res, a.applied)
	}
	for i, idx := range a.applied {
		if idx != i {
			t.Fatalf("chunk order %v: a chunk was applied twice or skipped", a.applied)
		}
	}
	if s := e.state(); s.Applied != 1 || s.InProgress != 0 || c2.Stats().Resumes != 1 {
		t.Fatalf("state %+v stats %+v", s, c2.Stats())
	}
}

func TestCorruptedChunkStopsThenResumesAfterRepair(t *testing.T) {
	e := newEnv(t)
	dir, m := release(t, e.root, 1, dataset(2000, nil), nil, e.signer())
	e.primary.set(dir)
	bad := m.Chunks()[3].Ref.SHA256
	path := filepath.Join(dir, ChunkFile(bad))
	good, _ := os.ReadFile(path)
	broken := append([]byte{}, good...)
	broken[len(broken)/2] ^= 0xff
	_ = os.WriteFile(path, broken, 0o644)

	a := newApplier()
	c, _ := e.consumer(a)
	_, err := c.Run(context.Background())
	if !errors.Is(err, transfer.ErrHashMismatch) {
		t.Fatalf("err = %v", err)
	}
	if s := e.state(); s.Applied != 0 || s.NextChunk != 3 || len(a.applied) != 3 {
		t.Fatalf("state %+v applied %v", s, a.applied)
	}
	_ = os.WriteFile(path, good, 0o644)
	res, err := c.Run(context.Background())
	if err != nil || !res.Resumed || e.state().Applied != 1 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestMirrorFailover(t *testing.T) {
	e := newEnv(t)
	dir, _ := release(t, e.root, 1, dataset(500, nil), nil, e.signer())
	e.primary.fail = true
	mirror := &origin{dir: dir}
	ms := httptest.NewServer(mirror)
	defer ms.Close()
	a := newApplier()
	c, f := e.consumer(a, transfer.Origin{URL: ms.URL, Name: "mirror"})
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(a.recs) != 500 || f.Stats().Fallbacks == 0 {
		t.Fatalf("recs %d stats %+v", len(a.recs), f.Stats())
	}
}

func TestAirGappedDirectory(t *testing.T) {
	e := newEnv(t)
	dir, _ := release(t, e.root, 1, dataset(300, nil), nil, e.signer())
	e.primary.fail = true
	a := newApplier()
	c, _ := e.consumer(a, transfer.Origin{Dir: dir})
	if _, err := c.Run(context.Background()); err != nil || len(a.recs) != 300 {
		t.Fatalf("%v recs %d", err, len(a.recs))
	}
}

func TestReplayOfOldSequenceIsRefused(t *testing.T) {
	e := newEnv(t)
	d1 := dataset(400, nil)
	dir1, _ := release(t, e.root, 1, d1, nil, e.signer())
	dir2, _ := release(t, e.root, 2, dataset(400, map[string]int{"r000001": 2}), d1, e.signer())
	e.primary.set(dir2)
	a := newApplier()
	c, _ := e.consumer(a)
	if _, err := c.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := len(a.applied)
	e.primary.set(dir1) // a stale mirror or a replay
	if _, err := c.Run(context.Background()); !errors.Is(err, ErrRollback) {
		t.Fatalf("err = %v", err)
	}
	if len(a.applied) != n || e.state().Applied != 2 || a.recs["r000001"].V != 2 {
		t.Fatal("an old sequence was applied")
	}
	if c.Stats().Refused != 1 {
		t.Fatalf("stats %+v", c.Stats())
	}
}

func TestDeltaOnlyOnItsBase(t *testing.T) {
	e := newEnv(t)
	d1 := dataset(400, nil)
	_, _ = release(t, e.root, 1, d1, nil, e.signer())
	dir2, _ := release(t, e.root, 2, dataset(400, map[string]int{"r000001": 2}), d1, e.signer())
	e.primary.set(dir2)
	a := newApplier()
	c, _ := e.consumer(a)
	res, err := c.Run(context.Background()) // applied 0: the delta's base 1 is missing
	if err != nil || res.Kind != KindSnapshot || len(a.recs) != 400 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestRefusedBeforeAnyChunk(t *testing.T) {
	cases := map[string]func(e *env, dir string){
		"untrusted key": func(e *env, dir string) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			e.priv = other
		},
		"expired": func(e *env, _ string) { e.now = t0.Add(30 * 24 * time.Hour) },
		"manifest swapped": func(e *env, dir string) {
			// A validly signed manifest of another bundle under the pinned name.
			src, _ := os.ReadFile(filepath.Join(dir, ManifestFile(KindSnapshot)))
			var m Manifest
			payload, _ := NewEd25519Verifier(e.pub).Verify(src, ManifestPayloadType(feed))
			_ = json.Unmarshal(payload, &m)
			m.Streams[0].Chunks = m.Streams[0].Chunks[:1]
			m.Streams[0].Records = m.Streams[0].Chunks[0].Records
			b, _ := json.Marshal(m)
			env, _ := e.signer().Sign(ManifestPayloadType(feed), b)
			_ = os.WriteFile(filepath.Join(dir, ManifestFile(KindSnapshot)), env, 0o644)
		},
		"pointer of another feed": func(e *env, dir string) {
			raw, _ := os.ReadFile(filepath.Join(dir, PointerFile))
			payload, _ := NewEd25519Verifier(e.pub).Verify(raw, PointerPayloadType(feed))
			env, _ := e.signer().Sign(PointerPayloadType("otherfeed"), payload)
			_ = os.WriteFile(filepath.Join(dir, PointerFile), env, 0o644)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			pub := e.pub
			dir, _ := release(t, e.root, 1, dataset(300, nil), nil, e.signer())
			mutate(e, dir)
			e.pub = pub
			e.primary.set(dir)
			a := newApplier()
			c, _ := e.consumer(a)
			if name == "untrusted key" {
				c.cfg.Verifier = NewEd25519Verifier(e.priv.Public().(ed25519.PublicKey))
			}
			_, err := c.Run(context.Background())
			if err == nil {
				t.Fatal("accepted")
			}
			if e.primary.chunks.Load() != 0 || len(a.applied) != 0 || e.state().InProgress != 0 {
				t.Fatalf("work done before refusal: chunks=%d applied=%v", e.primary.chunks.Load(), a.applied)
			}
			if c.Stats().Refused != 1 {
				t.Fatalf("err %v not counted as refused", err)
			}
		})
	}
}

// resign rewrites the snapshot manifest after edit and re-pins the pointer.
func resign(t *testing.T, e *env, dir string, edit func(*Manifest)) {
	t.Helper()
	v := NewEd25519Verifier(e.pub)
	raw, _ := os.ReadFile(filepath.Join(dir, ManifestFile(KindSnapshot)))
	payload, err := v.Verify(raw, ManifestPayloadType(feed))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	_ = json.Unmarshal(payload, &m)
	edit(&m)
	ref, err := writeSigned(dir, ManifestFile(KindSnapshot), ManifestPayloadType(feed), &m, e.signer())
	if err != nil {
		t.Fatal(err)
	}
	praw, _ := os.ReadFile(filepath.Join(dir, PointerFile))
	pp, _ := v.Verify(praw, PointerPayloadType(feed))
	var p Pointer
	_ = json.Unmarshal(pp, &p)
	p.Snapshot = ref
	if err := WritePointer(dir, p, e.signer()); err != nil {
		t.Fatal(err)
	}
}

func TestChunkContentChecks(t *testing.T) {
	cases := map[string]struct {
		edit func(*Manifest)
		lim  Limits
		want error
	}{
		"decompression larger than declared": {edit: func(m *Manifest) { m.Streams[0].Chunks[0].Uncompressed /= 2 }, want: ErrChunk},
		"fewer records than declared": {edit: func(m *Manifest) {
			m.Streams[0].Chunks[0].Records++
			m.Streams[0].Records++
		}, want: ErrChunk},
		"chunk count cap":  {lim: Limits{MaxChunks: 2}, want: ErrInvalid},
		"chunk size cap":   {lim: Limits{MaxChunkBytes: 100}, want: ErrInvalid},
		"record line cap":  {lim: Limits{MaxRecordBytes: 8}, want: ErrChunk},
		"stream sum wrong": {edit: func(m *Manifest) { m.Streams[0].Records = 1 }, want: ErrInvalid},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			dir, _ := release(t, e.root, 1, dataset(500, nil), nil, e.signer())
			if tc.edit != nil {
				resign(t, e, dir, tc.edit)
			}
			e.primary.set(dir)
			a := newApplier()
			c, _ := e.consumer(a)
			c.cfg.Limits = tc.lim.withDefaults()
			_, err := c.Run(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if e.state().Applied != 0 || len(a.recs) != 0 {
				t.Fatal("partial bundle marked applied or records committed")
			}
		})
	}
}

func TestWriterRules(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewWriter(dir, WriterOptions{Feed: "Bad Feed", Sequence: 1, Kind: KindSnapshot}); err == nil {
		t.Error("bad feed name accepted")
	}
	if _, err := NewWriter(dir, WriterOptions{Feed: feed, Sequence: 2, Kind: KindDelta, BaseSequence: 2}); err == nil {
		t.Error("delta on its own sequence accepted")
	}
	w, _ := NewWriter(dir, WriterOptions{Feed: feed, Sequence: 1, Kind: KindSnapshot})
	if err := w.Add("a", []byte(`{}`)); err == nil {
		t.Error("Add before Stream accepted")
	}
	_ = w.Stream("s")
	_ = w.Add("b", []byte(`{}`))
	if err := w.Add("a", []byte(`{}`)); err == nil {
		t.Error("descending id accepted")
	}
	if err := w.Add("c", []byte("{}\n{}")); err == nil {
		t.Error("multi-line record accepted")
	}
	if err := w.Stream("s"); err == nil {
		t.Error("duplicate stream accepted")
	}
}

func TestFileCheckpointIsPrivate(t *testing.T) {
	cp := FileCheckpoint{Path: filepath.Join(t.TempDir(), "x", "cp.json")}
	if err := cp.Save(context.Background(), State{Feed: feed, Applied: 3}); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(cp.Path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	s, err := cp.Load(context.Background())
	if err != nil || s.Applied != 3 {
		t.Fatalf("%+v %v", s, err)
	}
}
