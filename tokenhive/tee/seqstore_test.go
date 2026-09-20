package tee

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func openTestStore(t *testing.T, path string) SeqStore {
	t.Helper()
	store, err := NewFileSeqStore(path)
	if err != nil {
		t.Fatalf("open seqstore: %v", err)
	}
	return store
}

func nextValue(t *testing.T, store SeqStore, provider string) uint64 {
	t.Helper()
	got, err := store.Next([]byte(provider))
	if err != nil {
		t.Fatalf("Next(%s): %v", provider, err)
	}
	return got
}

func closeTestStore(t *testing.T, store SeqStore) {
	t.Helper()
	if err := store.Close(); err != nil {
		t.Fatalf("close seqstore: %v", err)
	}
}

// TestFileSeqStoreContinuesAfterRestart pins what the counter is for: a number
// that reached a receipt is still spent after the process that issued it ends,
// so the next run cannot reissue it.
func TestFileSeqStoreContinuesAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqstore.log")

	first := openTestStore(t, path)
	for want := uint64(1); want <= 3; want++ {
		if got := nextValue(t, first, "prov-a"); got != want {
			t.Fatalf("prov-a = %d, want %d", got, want)
		}
	}
	nextValue(t, first, "prov-b")
	closeTestStore(t, first)

	second := openTestStore(t, path)
	defer closeTestStore(t, second)
	if got := nextValue(t, second, "prov-a"); got != 4 {
		t.Fatalf("prov-a after restart = %d, want 4", got)
	}
	got, err := second.Peek([]byte("prov-b"))
	if err != nil || got != 1 {
		t.Fatalf("Peek(prov-b) = %d, %v, want 1, nil", got, err)
	}
}

// TestFileSeqStoreAppendsOneRecordPerNumber is the cost property: issuing a
// number extends the log rather than rewriting every provider's counter.
func TestFileSeqStoreAppendsOneRecordPerNumber(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqstore.log")
	store := openTestStore(t, path)

	nextValue(t, store, "prov-a")
	nextValue(t, store, "prov-b")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	nextValue(t, store, "prov-a")
	closeTestStore(t, store)

	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := string(before) + "prov-a 2\n"; string(after) != want {
		t.Fatalf("log = %q, want %q", after, want)
	}
}

// TestFileSeqStoreDropsATornTail covers the crash case: a half-written record
// was never returned to anyone, so it is dropped rather than counted — and cut
// off, so the next append cannot splice a record out of the two.
func TestFileSeqStoreDropsATornTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqstore.log")
	store := openTestStore(t, path)
	nextValue(t, store, "prov-a")
	nextValue(t, store, "prov-a")
	closeTestStore(t, store)

	whole, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(whole, "prov-a 9"...), 0o600); err != nil {
		t.Fatal(err)
	}

	reopened := openTestStore(t, path)
	defer closeTestStore(t, reopened)
	if got, err := reopened.Peek([]byte("prov-a")); err != nil || got != 2 {
		t.Fatalf("Peek after a torn tail = %d, %v, want 2, nil", got, err)
	}
	if got := nextValue(t, reopened, "prov-a"); got != 3 {
		t.Fatalf("Next after a torn tail = %d, want 3", got)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(after), "9") {
		t.Fatalf("torn record survived: %q", after)
	}
}

// TestFileSeqStoreRefusesACorruptRecord keeps a damaged log from being read as
// a short one: an unreadable file is indistinguishable from a tampered one, and
// starting from zero would reissue numbers already in receipts.
func TestFileSeqStoreRefusesACorruptRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqstore.log")
	if err := os.WriteFile(path, []byte("prov-a 3\nprov-b oops\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileSeqStore(path); err == nil {
		t.Fatal("a corrupt log was accepted")
	}
}

// TestFileSeqStoreRefusesAnUnrepresentableProviderID pins the format's one
// assumption: the ID is the line's key, so an ID that could forge a separator
// is refused instead of escaped.
func TestFileSeqStoreRefusesAnUnrepresentableProviderID(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "seqstore.log"))
	defer closeTestStore(t, store)
	if _, err := store.Next([]byte("prov a")); err == nil {
		t.Fatal("a provider id containing a space was accepted")
	}
}

// assertLogBounded checks the log is not growing with the number of jobs: one
// record per provider plus the floor's slack, and no more.
func assertLogBounded(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if lines, max := strings.Count(string(raw), "\n"), 4*1+seqLogCompactFloor; lines > max {
		t.Fatalf("log holds %d records, want at most %d", lines, max)
	}
}

// TestFileSeqStoreCompactsAGrownLog checks the bound holds while the service is
// running, not only at startup: issuing enough numbers rewrites the log back to
// one record per provider. The rewrite replaces the file the append handle
// points at, so this also pins that the numbers issued after it are not written
// to the unlinked inode the old handle names — they have to be readable by the
// next process.
func TestFileSeqStoreCompactsAGrownLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seqstore.log")

	store := openTestStore(t, path)
	var last uint64
	for i := 0; i < 2*seqLogCompactFloor; i++ {
		last = nextValue(t, store, "prov-a")
	}
	assertLogBounded(t, path)
	closeTestStore(t, store)

	reopened := openTestStore(t, path)
	defer closeTestStore(t, reopened)
	if got, err := reopened.Peek([]byte("prov-a")); err != nil || got != last {
		t.Fatalf("Peek after compaction = %d, %v, want %d, nil", got, err, last)
	}
	if got := nextValue(t, reopened, "prov-a"); got != last+1 {
		t.Fatalf("Next after compaction = %d, want %d", got, last+1)
	}
	assertLogBounded(t, path)
}

// TestFileSeqStoreConcurrentNext checks the append is serialised: concurrent
// callers get distinct numbers, and the highest one is the one that persists.
func TestFileSeqStoreConcurrentNext(t *testing.T) {
	const writers, each = 8, 16
	path := filepath.Join(t.TempDir(), "seqstore.log")
	store := openTestStore(t, path)

	seen := make(map[uint64]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < each; i++ {
				got, err := store.Next([]byte("prov-a"))
				if err != nil {
					t.Errorf("Next: %v", err)
					return
				}
				mu.Lock()
				seen[got] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	closeTestStore(t, store)

	if len(seen) != writers*each {
		t.Fatalf("%d distinct numbers, want %d", len(seen), writers*each)
	}
	if seen[0] || !seen[writers*each] {
		t.Fatalf("numbers are not 1..%d: zero=%v top=%v", writers*each, seen[0], seen[writers*each])
	}
	reopened := openTestStore(t, path)
	defer closeTestStore(t, reopened)
	if got, err := reopened.Peek([]byte("prov-a")); err != nil || got != writers*each {
		t.Fatalf("Peek after concurrent writers = %d, %v, want %d, nil", got, err, writers*each)
	}
}
