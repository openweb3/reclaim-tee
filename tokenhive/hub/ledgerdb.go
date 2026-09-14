package hub

import (
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"time"

	// Pure Go, no cgo: the ledger cross-compiles with the rest of the Hub and
	// runs wherever the binary does, including the minimal SNP image.
	_ "modernc.org/sqlite"
)

// SyncMode selects how hard the ledger makes a commit. It is the one knob that
// trades money-safety for throughput, so it is explicit at every call site and
// refused in serve mode unless it is a mode a real balance may run on.
type SyncMode string

const (
	// SyncFull fsyncs the write-ahead log on every commit. A committed charge
	// survives a power cut. This is the default and the only mode a Hub that
	// holds other people's money should run.
	SyncFull SyncMode = "full"

	// SyncNormal commits without fsyncing the log. Committed transactions
	// survive a process crash but a power cut can roll back the last commits.
	// Acceptable for a benchmark on a machine nobody pays through.
	SyncNormal SyncMode = "normal"

	// SyncOff lets the operating system decide when the log reaches disk.
	// Simulation only: refused in serve mode, because a crash can then lose
	// charges the Hub already told a buyer and a seller were booked.
	SyncOff SyncMode = "off"
)

// ledgerSchemaVersion is stamped into the database's user_version so a future
// migration can tell what it is opening.
const ledgerSchemaVersion = 1

// ledgerSchema is the whole durable shape of the ledger. Grouped here rather
// than scattered across the operations so the invariants are readable in one
// place:
//
//   - accounts: one row per account, three roles in one table so a settlement
//     updates all sides of a transfer in a single transaction. balance is what
//     the account owns; held is what is frozen against in-flight orders. A
//     settlement is a pure transfer between these rows — no account is created
//     with money it did not receive from somewhere else.
//   - orders: one row per job, keyed by the job id the Hub mints before
//     dispatch. This is what makes a charge idempotent: replaying a settlement
//     finds the row already booked and refuses to book it twice.
//   - journal: the append-only record of every money movement, written in the
//     same transaction as the balance change it describes. Its unique
//     (kind, tx) index is the durable idempotency barrier for externally
//     named transactions.
//   - ledger_state: the conserved quantity. Σ balances may only change when
//     money enters from outside (a seed today, a real deposit later), and this
//     single row carries both sides of that identity, so the CHECK constraint
//     below refuses — at write time — any funding that is only half recorded.
const ledgerSchema = `
CREATE TABLE IF NOT EXISTS accounts (
	role    TEXT    NOT NULL CHECK (role IN ('buyer', 'seller', 'platform')),
	name    TEXT    NOT NULL,
	balance INTEGER NOT NULL CHECK (balance >= 0),
	held    INTEGER NOT NULL DEFAULT 0 CHECK (held >= 0 AND held <= balance),
	PRIMARY KEY (role, name)
) STRICT;

CREATE TABLE IF NOT EXISTS orders (
	id         TEXT    NOT NULL PRIMARY KEY,
	tenant     TEXT    NOT NULL,
	provider   TEXT    NOT NULL DEFAULT '',
	state      TEXT    NOT NULL CHECK (state IN ('held', 'settled', 'released', 'charged')),
	hold       INTEGER NOT NULL CHECK (hold >= 0),
	buyer      INTEGER NOT NULL DEFAULT 0 CHECK (buyer >= 0),
	seller     INTEGER NOT NULL DEFAULT 0 CHECK (seller >= 0),
	commission INTEGER NOT NULL DEFAULT 0 CHECK (commission >= 0),
	opened_at  INTEGER NOT NULL,
	closed_at  INTEGER NOT NULL DEFAULT 0,
	-- A booked order is exactly zero-sum: what the buyer is billed is what the
	-- seller earns plus what the Hub keeps. Trivially true while held.
	CHECK (buyer = seller + commission)
) STRICT;

CREATE INDEX IF NOT EXISTS orders_open ON orders (state) WHERE state = 'held';
CREATE INDEX IF NOT EXISTS orders_tenant ON orders (tenant);

CREATE TABLE IF NOT EXISTS journal (
	seq        INTEGER PRIMARY KEY AUTOINCREMENT,
	kind       TEXT    NOT NULL CHECK (kind IN ('seed', 'deposit', 'hold', 'settle', 'charge', 'release')),
	tx         TEXT    NOT NULL,
	tenant     TEXT    NOT NULL DEFAULT '',
	provider   TEXT    NOT NULL DEFAULT '',
	hold       INTEGER NOT NULL DEFAULT 0,
	buyer      INTEGER NOT NULL DEFAULT 0,
	seller     INTEGER NOT NULL DEFAULT 0,
	commission INTEGER NOT NULL DEFAULT 0,
	funded     INTEGER NOT NULL DEFAULT 0,
	at         INTEGER NOT NULL
) STRICT;

-- The idempotency barrier. kind namespaces the key (a job id and an external
-- payment reference can never collide), and because the row is written in the
-- same transaction as the balance it describes, a crash between the two is
-- impossible: the movement and its record share one commit.
CREATE UNIQUE INDEX IF NOT EXISTS journal_tx ON journal (kind, tx);

CREATE TABLE IF NOT EXISTS ledger_state (
	id     INTEGER NOT NULL PRIMARY KEY CHECK (id = 1),
	booked INTEGER NOT NULL CHECK (booked >= 0),
	funded INTEGER NOT NULL CHECK (funded >= 0),
	CHECK (booked = funded)
) STRICT;
`

// AccountsOption configures OpenAccounts.
type AccountsOption func(*accountsConfig)

type accountsConfig struct {
	sync SyncMode
}

// WithSync selects the durability of every commit. See SyncMode.
func WithSync(mode SyncMode) AccountsOption {
	return func(c *accountsConfig) { c.sync = mode }
}

// validSyncMode reports whether mode is one the ledger knows.
func validSyncMode(mode SyncMode) bool {
	switch mode {
	case SyncFull, SyncNormal, SyncOff:
		return true
	default:
		return false
	}
}

// ledgerDSN builds the connection string for one of the ledger's two handles.
//
// Every pragma is per-connection, so they travel in the DSN rather than being
// issued once at open: database/sql may open further connections later, and a
// connection without synchronous(FULL) or busy_timeout would silently weaken
// the durability of whatever commits on it. journal_mode is the exception —
// WAL is a property of the file, set once and remembered.
func ledgerDSN(path string, sync SyncMode, write bool) string {
	q := url.Values{}
	for _, pragma := range []string{
		// Wait for the write lock instead of failing the commit: with one
		// writer connection in this process, contention can only come from
		// another process (an operator's sqlite3 session, a backup).
		"busy_timeout(10000)",
		"journal_mode(WAL)",
		"foreign_keys(ON)",
		"synchronous(" + string(sync) + ")",
	} {
		q.Add("_pragma", pragma)
	}
	if write {
		// Take the write lock when the transaction begins. A deferred
		// transaction that upgrades mid-way can fail after doing work, which
		// on a money path is a lost charge rather than a retry.
		q.Set("_txlock", "immediate")
	}
	u := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: q.Encode()}
	return u.String()
}

// openLedger opens the two handles the ledger runs on.
//
// SQLite is a single-writer database and this is a single-writer system, so the
// shape is deliberately literal: one writer connection, capped at one, whose
// every transaction is IMMEDIATE and therefore serialized by construction; and
// a pool of reader connections, which in WAL mode read a consistent snapshot
// without ever blocking the writer or each other. Nothing about a balance
// query touches the writer's lock, and nothing about a charge queues behind a
// read.
//
// The rest of the package therefore needs no mutex around money: two
// concurrent settlements cannot interleave, because the second one cannot
// begin until the first commits.
func openLedger(path string, sync SyncMode) (w, r *sql.DB, err error) {
	if path == "" {
		return nil, nil, errors.New("ledger path is empty")
	}
	if !validSyncMode(sync) {
		return nil, nil, fmt.Errorf("unknown ledger sync mode %q (want full, normal or off)", sync)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		// The ledger owns its directory: the database is private to the
		// process that holds other people's money.
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create ledger directory %s: %w", dir, err)
		}
	}

	w, err = sql.Open("sqlite", ledgerDSN(path, sync, true))
	if err != nil {
		return nil, nil, fmt.Errorf("open ledger %s: %w", path, err)
	}
	// One writer connection, kept warm: it is the lock the money path takes.
	w.SetMaxOpenConns(1)
	w.SetMaxIdleConns(1)

	if err := migrate(w); err != nil {
		w.Close()
		return nil, nil, err
	}

	// A separate handle so reads never queue behind the writer connection.
	// WAL readers see the last committed snapshot and take no lock the writer
	// needs, so the pool can be as wide as the machine.
	r, err = sql.Open("sqlite", ledgerDSN(path, sync, false))
	if err != nil {
		w.Close()
		return nil, nil, fmt.Errorf("open ledger %s for reading: %w", path, err)
	}
	r.SetMaxOpenConns(8)
	r.SetMaxIdleConns(8)

	if _, err := w.Exec(`INSERT OR IGNORE INTO ledger_state (id, booked, funded) VALUES (1, 0, 0)`); err != nil {
		r.Close()
		w.Close()
		return nil, nil, fmt.Errorf("initialise ledger %s: %w", path, err)
	}
	return w, r, nil
}

// migrate applies the schema and refuses to open a database written by a
// version of the Hub that this binary does not understand. Schema changes are
// rare and money-bearing, so an unknown version is a startup failure with an
// operator in the loop rather than an automatic upgrade.
func migrate(w *sql.DB) error {
	var version int
	if err := w.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read ledger schema version: %w", err)
	}
	if version > ledgerSchemaVersion {
		return fmt.Errorf("ledger schema version %d is newer than this binary understands (%d)", version, ledgerSchemaVersion)
	}
	if _, err := w.Exec(ledgerSchema); err != nil {
		return fmt.Errorf("create ledger schema: %w", err)
	}
	if version < ledgerSchemaVersion {
		if _, err := w.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, ledgerSchemaVersion)); err != nil {
			return fmt.Errorf("stamp ledger schema version: %w", err)
		}
	}
	return nil
}

// queryer is the read half of *sql.DB and *sql.Tx, so a helper can run inside
// a write transaction or against the reader pool without caring which.
type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

// toMicros converts a uint64 amount to the int64 the database stores. Amounts
// above int64 are refused rather than wrapped: an amount that cannot be
// represented cannot be booked.
func toMicros(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, fmt.Errorf("amount %d does not fit the ledger's 64-bit columns", v)
	}
	return int64(v), nil
}

// microsOf reads a stored column back as the uint64 the Hub speaks in.
func microsOf(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// nowMicros is the ledger's timestamp source, in microseconds since the epoch
// so that ordering survives short-lived processes and sub-second bursts.
func nowMicros() int64 { return time.Now().UnixMicro() }
