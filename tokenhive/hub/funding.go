package hub

import (
	"database/sql"
	"errors"
	"fmt"
)

// ErrTransactionConflict means an external transaction id was presented again
// with terms other than the ones it was booked with: a different amount, or a
// different account. The first booking stands and the second is refused —
// money enters the ledger once per external transaction, so quoting an id that
// is already applied for another amount is a caller bug or an attempt to
// credit twice.
//
// The same id with the same terms is not a conflict: it is exactly the retry a
// payment module is supposed to make, and it succeeds without crediting twice.
var ErrTransactionConflict = errors.New("external transaction already applied with different terms")

// fund books one credit that enters the ledger from outside: the buyer's
// balance and the ledger's conserved total grow together, and the journal
// records where the money came from.
//
// This is the money seam an external payment module calls. txID is that
// module's own transaction id — its payment reference, not a Hub job id — and
// it is the idempotency key, so a module that charges a card and then crashes
// before telling the Hub can retry the same id forever and the buyer is
// credited exactly once. Payment references have their own key space (the
// journal's unique index is on (kind, tx)), so they can never collide with a
// job id.
//
// kind labels the record: 'seed' today, 'deposit' once the payment module
// lands. Only the label differs, which is the point — "money entered from
// outside" stays one code path instead of one per caller, and a caller cannot
// get the retry semantics wrong by writing the statements itself.
//
// Everything a caller can get wrong here is a refusal, not a latch: this is the
// only entry point that takes its terms from outside the process, and a
// malformed request must not stop the Hub from billing anyone. The rule is the
// same one the rest of the ledger follows — latch when the books contradict
// themselves, refuse when a request cannot be honoured.
func (a *Accounts) fund(kind, txID, tenant string, amount uint64) error {
	if txID == "" {
		return refuse(fmt.Errorf("%s with an empty transaction id cannot be applied idempotently", kind))
	}
	if tenant == "" {
		return refuse(fmt.Errorf("%s %q names no account to credit", kind, txID))
	}
	if amount == 0 {
		return refuse(fmt.Errorf("%s %q credits nothing", kind, txID))
	}
	micros, err := toMicros(amount)
	if err != nil {
		return refuse(fmt.Errorf("%s %q: %w", kind, txID, err))
	}
	return a.write(func(tx *sql.Tx) error {
		return fundTx(tx, kind, txID, tenant, micros)
	})
}

// fundTx applies one external credit inside an already-open transaction. The
// caller has validated the terms; this is the atomic part, and it is all of it
// — a credit that lands without its journal record, or with the conserved total
// updated on only one side, is what the transaction (and the CHECK on
// ledger_state) exists to exclude.
func fundTx(tx *sql.Tx, kind, txID, tenant string, micros int64) error {
	have, applied, err := appliedTx(tx, kind, txID)
	if err != nil {
		return err
	}
	if applied {
		if have.tenant == tenant && have.micros == micros {
			// The retry of a credit that is already booked. Reporting success
			// is the whole point: the caller cannot tell whether its first
			// attempt landed, and either answer must leave one credit.
			return nil
		}
		return refuse(fmt.Errorf("%w: %s %s already credited %d to %q, not %d to %q",
			ErrTransactionConflict, kind, txID, have.micros, have.tenant, micros, tenant))
	}
	if _, err := tx.Exec(`INSERT INTO accounts (role, name, balance, held) VALUES (?, ?, ?, 0)
		ON CONFLICT (role, name) DO UPDATE SET balance = balance + excluded.balance`,
		roleBuyer, tenant, micros); err != nil {
		return fmt.Errorf("fund %s %s: %w", kind, txID, err)
	}
	// Both sides of the conserved identity move in one statement, so its CHECK
	// never sees them disagree.
	if _, err := tx.Exec(`UPDATE ledger_state SET booked = booked + ?, funded = funded + ? WHERE id = 1`, micros, micros); err != nil {
		return fmt.Errorf("fund %s %s: %w", kind, txID, err)
	}
	return insertJournal(tx, journalEntry{kind: kind, tx: txID, tenant: tenant, funded: micros, at: nowMicros()})
}

// funding is one external credit that has already been booked: which account it
// landed on and how much. Both are compared, because the transaction id names
// the whole booking. A reference that credited alice is not the same reference
// when it is presented for bob — honouring that would let one payment credit
// two accounts, which is the one thing the id is there to prevent.
type funding struct {
	tenant string
	micros int64
}

// appliedTx reports whether an external transaction id has already been
// booked, and on what terms. It reads inside the write transaction that would
// apply it, so the answer cannot go stale between the check and the write.
//
// The unique index on (kind, tx) still stands behind this: the check is what
// turns a duplicate into a clean, idempotent answer, and the index is what
// makes crediting twice impossible even if a future caller forgets to ask.
func appliedTx(tx *sql.Tx, kind, txID string) (funding, bool, error) {
	var have funding
	err := tx.QueryRow(`SELECT tenant, funded FROM journal WHERE kind = ? AND tx = ?`, kind, txID).
		Scan(&have.tenant, &have.micros)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return funding{}, false, nil
	case err != nil:
		return funding{}, false, fmt.Errorf("read journal %s %s: %w", kind, txID, err)
	}
	return have, true, nil
}

// seed writes the first-boot balances through the same funding path a real
// deposit takes. It runs only on an empty ledger, and every balance is recorded
// as funding, so the conserved quantity starts from what was actually put in
// rather than from nothing. The whole genesis is one transaction: with several
// tenants listed, a failure on the last one must not leave the first ones
// funded.
//
// The transaction id of a seed is the tenant itself: seeding is a
// once-per-tenant act by construction (it only runs on an empty ledger), so it
// has no external reference to quote.
func (a *Accounts) seed(seeds map[string]uint64) error {
	if len(seeds) == 0 {
		return nil
	}
	// Validate everything before booking anything: a typo must not leave a
	// tenant partially funded.
	amounts := make(map[string]int64, len(seeds))
	for tenant, amount := range seeds {
		if tenant == "" {
			return errors.New("accounts seed with empty tenant name")
		}
		if amount == 0 {
			return fmt.Errorf("accounts seed for tenant %q is zero, which would fund nothing", tenant)
		}
		micros, err := toMicros(amount)
		if err != nil {
			return err
		}
		amounts[tenant] = micros
	}
	return a.write(func(tx *sql.Tx) error {
		for tenant, micros := range amounts {
			if err := fundTx(tx, kindSeed, tenant, tenant, micros); err != nil {
				return err
			}
		}
		return nil
	})
}
