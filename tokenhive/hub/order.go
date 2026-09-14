package hub

import (
	"database/sql"
	"errors"
	"fmt"
)

// Journal record kinds. Each is an entry in the append-only money log, written
// in the same transaction as the movement it describes.
const (
	// kindSeed is money entering the ledger from the first-boot seed. It is a
	// stand-in for a real deposit (kindDeposit), which a payment module will
	// write through the same path.
	kindSeed = "seed"
	// kindDeposit is money entering from an external payment that the operator
	// has already confirmed. No caller writes it yet: the funding side of the
	// design lands with the payment module.
	kindDeposit = "deposit"
	// kindHold freezes a tenant's balance before dispatch.
	kindHold = "hold"
	// kindSettle turns a hold into the buyer's charge and the seller's and
	// platform's credit.
	kindSettle = "settle"
	// kindCharge bills a buyer whose hold had already gone back.
	kindCharge = "charge"
	// kindRelease returns an unsettled hold.
	kindRelease = "release"
)

// journalEntry is one row of the money log.
type journalEntry struct {
	kind       string
	tx         string
	tenant     string
	provider   string
	hold       int64
	buyer      int64
	seller     int64
	commission int64
	// funded is the signed amount this record moved the conserved quantity by.
	// It is zero for every internal transfer: those move money between
	// accounts and cannot change the total.
	funded int64
	at     int64
}

const insertJournalSQL = `INSERT INTO journal (kind, tx, tenant, provider, hold, buyer, seller, commission, funded, at)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

// insertJournal appends one record. It runs inside the transaction that moved
// the money, so the movement and its record share a commit: there is no window
// in which one exists without the other, and the unique (kind, tx) index makes
// the record itself the durable idempotency barrier. A duplicate key here
// aborts the whole transaction, which is what stops an externally named
// transaction from being applied twice.
func insertJournal(tx *sql.Tx, e journalEntry) error {
	if _, err := tx.Exec(insertJournalSQL, e.kind, e.tx, e.tenant, e.provider,
		e.hold, e.buyer, e.seller, e.commission, e.funded, e.at); err != nil {
		return fmt.Errorf("journal %s %s: %w", e.kind, e.tx, err)
	}
	return nil
}

// ledgerOrder is one orders row, in the int64 shape the database stores.
type ledgerOrder struct {
	id         string
	tenant     string
	provider   string
	state      string
	hold       int64
	buyer      int64
	seller     int64
	commission int64
	openedAt   int64
	closedAt   int64
}

func (o ledgerOrder) order() Order {
	return Order{
		ID:         o.id,
		Tenant:     o.tenant,
		Provider:   o.provider,
		State:      o.state,
		Hold:       microsOf(o.hold),
		Buyer:      microsOf(o.buyer),
		Seller:     microsOf(o.seller),
		Commission: microsOf(o.commission),
		OpenedAt:   o.openedAt,
		ClosedAt:   o.closedAt,
	}
}

// holdMicros is the order's reservation in the column's own type.
func (o ledgerOrder) holdMicros() int64 { return o.hold }

const selectOrderSQL = `SELECT id, tenant, provider, state, hold, buyer, seller, commission, opened_at, closed_at
	FROM orders WHERE id = ?`

// getOrder reads one order. The second result reports whether it exists, which
// is not an error: admission asks before opening one.
func getOrder(q queryer, orderID string) (ledgerOrder, bool, error) {
	var o ledgerOrder
	err := q.QueryRow(selectOrderSQL, orderID).Scan(&o.id, &o.tenant, &o.provider, &o.state,
		&o.hold, &o.buyer, &o.seller, &o.commission, &o.openedAt, &o.closedAt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return ledgerOrder{id: orderID}, false, nil
	case err != nil:
		return ledgerOrder{id: orderID}, false, fmt.Errorf("read order %s: %w", orderID, err)
	}
	return o, true, nil
}
