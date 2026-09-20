package tee

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// ErrNoSeqStore means the service was built without a sequence store.
//
// It is a wiring error, deliberately not defaulted. A silent in-memory
// fallback would be worse than a refusal: the counter would reset on every
// restart, receipts would repeat sequence numbers, and a provider auditing for
// hidden receipts would compare an incoherent series and conclude nothing is
// missing. The one failure mode ProviderSeq exists to catch would be the one
// it silently stopped catching. Volatile storage therefore has to be asked for
// by name — see NewMemorySeqStore.
var ErrNoSeqStore = errors.New("no sequence store configured")

// SeqStore assigns and tracks the per-provider monotonic sequence number the
// TEE signs into every receipt (proof.Receipt.ProviderSeq).
//
// This is the only stateful component in the enclave. The interface is kept
// this small so the production backend (a blob sealed under the platform
// sealing key) and the development backend (a plain file) are interchangeable
// without the execution path knowing which one it has.
//
// A provider that has never been used starts at zero, so the first number
// issued is 1. Implementations must be safe for concurrent use and must not
// return a number they have not yet durably recorded: a sequence number that
// survives in a receipt but not in the store would be reissued after a
// restart, and two different receipts bearing the same number destroy the
// audit property.
type SeqStore interface {
	// Next advances providerID's counter and returns the new value.
	Next(providerID []byte) (uint64, error)

	// Peek returns the current value without advancing it. It exists for
	// operators and for startup logging — "resuming provider X at N" is how a
	// deployment confirms its counters actually survived a restart.
	Peek(providerID []byte) (uint64, error)

	// Close flushes and releases resources.
	Close() error
}

// memorySeqStore keeps counters in process memory only.
type memorySeqStore struct {
	mu   sync.Mutex
	data map[string]uint64
}

// NewMemorySeqStore returns a volatile sequence store.
//
// Counters are lost when the process exits, which breaks the cross-restart
// guarantee ProviderSeq is for. That makes it correct for exactly two uses:
// unit tests, and the in-memory fake TEE that Hub business tests run against.
// It must never back a TEE that issues receipts a provider will settle
// against.
func NewMemorySeqStore() SeqStore {
	return &memorySeqStore{data: make(map[string]uint64)}
}

func (s *memorySeqStore) Next(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[string(providerID)]++
	return s.data[string(providerID)], nil
}

func (s *memorySeqStore) Peek(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[string(providerID)], nil
}

func (s *memorySeqStore) Close() error { return nil }

// fileSeqStore persists counters as an append-only log of "<provider> <seq>"
// lines, one line per number issued. Appending is what makes Next both cheap
// and honest: a job costs one small write and one fsync, never a rewrite of
// every provider's counter, and the number is on disk before it is returned.
//
// The log is bounded, not linear: once it holds well past one record per
// provider it is rewritten in place (see compact), so its size tracks the size
// of the market rather than the number of jobs ever run. One process per file:
// the counters live in memory as well as on disk.
type fileSeqStore struct {
	mu    sync.Mutex
	path  string
	data  map[string]uint64
	lines int
	file  *os.File
}

// NewFileSeqStore opens, or initialises, a file-backed sequence store.
//
// It is the development and simulation backend: the counters genuinely survive
// process restarts, which is what makes gap detection testable on a laptop,
// and it pulls in no cryptography. The production backend seals the same map
// under the platform sealing key; only the constructor changes.
func NewFileSeqStore(path string) (SeqStore, error) {
	s := &fileSeqStore{path: path, data: make(map[string]uint64)}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("seqstore: create dir: %w", err)
	}
	whole, torn, err := s.load()
	if err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("seqstore: open %s: %w", path, err)
	}
	s.file = file

	if torn {
		// A crash can leave a partial record behind. The number it was writing
		// was never returned to anyone, so the fragment is dropped — and cut
		// off the file, because leaving it there would splice it onto the next
		// append and invent a record naming a provider that never wrote it.
		if err := file.Truncate(whole); err != nil {
			s.Close()
			return nil, fmt.Errorf("seqstore: truncate %s: %w", path, err)
		}
	}
	if s.compactNeededLocked() {
		if err := s.compact(); err != nil {
			s.Close()
			return nil, err
		}
	}
	return s, nil
}

// compactNeededLocked reports whether the log has grown past the point where a
// rewrite costs less than carrying it: one record per provider plus slack.
// Callers hold mu.
func (s *fileSeqStore) compactNeededLocked() bool {
	return s.lines > 4*len(s.data)+seqLogCompactFloor
}

// handleLocked returns the append handle, reopening the file when a compaction
// had to drop it. Callers hold mu.
func (s *fileSeqStore) handleLocked() (*os.File, error) {
	if s.file != nil {
		return s.file, nil
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("seqstore: open %s: %w", s.path, err)
	}
	s.file = file
	return file, nil
}

// Next appends the new number and fsyncs it before returning, so a number that
// reaches a receipt has already survived a crash. On any failure the counter is
// left where it was, rather than drifting ahead of the file.
func (s *fileSeqStore) Next(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := string(providerID)
	next := s.data[key] + 1
	record, err := seqLogRecord(key, next)
	if err != nil {
		return 0, err
	}
	file, err := s.handleLocked()
	if err != nil {
		return 0, err
	}
	if _, err := file.Write(record); err != nil {
		return 0, fmt.Errorf("seqstore: append %s: %w", s.path, err)
	}
	if err := file.Sync(); err != nil {
		return 0, fmt.Errorf("seqstore: sync %s: %w", s.path, err)
	}
	s.data[key] = next
	s.lines++

	if s.compactNeededLocked() {
		// The number just issued is already durable, so a failed rewrite must
		// not fail the request: the log stays valid and the next append sees
		// the same condition and tries again. A rewrite that keeps failing
		// means a full disk, which the append itself will report.
		_ = s.compact()
	}
	return next, nil
}

func (s *fileSeqStore) Peek(providerID []byte) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.data[string(providerID)], nil
}

func (s *fileSeqStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		return nil
	}
	err := s.file.Close()
	s.file = nil
	return err
}

// seqLogCompactFloor keeps the log from being rewritten every few jobs: below
// this many records it is left alone however many providers it has. It is the
// slack above one-record-per-provider, so the file stays under a few kilobytes
// for a small market and a rewrite costs a fraction of the appends it covers.
const seqLogCompactFloor = 256

// load reads the log into memory and reports the offset of the end of the last
// whole record, plus whether a trailing fragment was found.
func (s *fileSeqStore) load() (int64, bool, error) {
	raw, err := os.ReadFile(s.path)
	switch {
	case os.IsNotExist(err):
		return 0, false, nil
	case err != nil:
		return 0, false, fmt.Errorf("seqstore: read %s: %w", s.path, err)
	}
	torn := len(raw) > 0 && raw[len(raw)-1] != '\n'
	if torn {
		raw = raw[:bytes.LastIndexByte(raw, '\n')+1]
	}

	lines := bytes.Split(raw, []byte("\n"))
	for _, line := range lines[:len(lines)-1] {
		key, seq, err := parseSeqRecord(line)
		if err != nil {
			// Refuse rather than start from zero. An unreadable counter
			// file is indistinguishable from a tampered one, and both
			// mean the next number issued would be a repeat.
			return 0, false, fmt.Errorf("seqstore: parse %s: %w", s.path, err)
		}
		s.data[key] = seq
		s.lines++
	}
	return int64(len(raw)), torn, nil
}

// compact rewrites the log as one record per provider, at startup and whenever
// Next finds it grown past compactNeededLocked. Callers hold mu.
func (s *fileSeqStore) compact() error {
	var buf bytes.Buffer
	for key, seq := range s.data {
		record, err := seqLogRecord(key, seq)
		if err != nil {
			return err
		}
		buf.Write(record)
	}

	tmp := s.path + ".tmp"
	file, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("seqstore: write %s: %w", tmp, err)
	}
	_, err = file.Write(buf.Bytes())
	if err == nil {
		err = file.Sync()
	}
	if cerr := file.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("seqstore: write %s: %w", tmp, err)
	}
	// Rename is atomic, so a crash mid-compaction leaves the previous log
	// intact. The directory sync is what makes the rename itself durable on
	// filesystems that need it; the rename has happened either way, so a
	// failure there is not fatal.
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("seqstore: rename %s: %w", tmp, err)
	}
	if dir, err := os.Open(filepath.Dir(s.path)); err == nil {
		dir.Sync()
		dir.Close()
	}

	// The rename replaced the file the append handle points at: that handle now
	// names an unlinked inode, and appends to it would be written where nothing
	// will ever read them. Swap the handle over before anything appends again,
	// and drop it if the swap fails so the next call reopens rather than
	// writing to the void.
	reopened, err := os.OpenFile(s.path, os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		s.file.Close()
		s.file = nil
		return fmt.Errorf("seqstore: reopen %s: %w", s.path, err)
	}
	s.file.Close()
	s.file = reopened
	s.lines = len(s.data)
	return nil
}

// seqLogRecord renders one log line. Provider IDs arrive as raw bytes, and a
// separator inside one would let two providers share a counter, so an ID that
// cannot be represented is refused instead of escaped: real provider names come
// from the Hub's validated rate cards and never contain whitespace.
func seqLogRecord(key string, seq uint64) ([]byte, error) {
	if key == "" || len(key) > 512 {
		return nil, fmt.Errorf("seqstore: unusable provider id %q", key)
	}
	for i := 0; i < len(key); i++ {
		if key[i] <= ' ' || key[i] == 0x7f {
			return nil, fmt.Errorf("seqstore: unusable provider id %q", key)
		}
	}
	return []byte(fmt.Sprintf("%s %d\n", key, seq)), nil
}

func parseSeqRecord(line []byte) (string, uint64, error) {
	key, value, ok := strings.Cut(string(line), " ")
	if !ok {
		return "", 0, fmt.Errorf("malformed record %q", line)
	}
	seq, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return "", 0, fmt.Errorf("malformed record %q", line)
	}
	return key, seq, nil
}
