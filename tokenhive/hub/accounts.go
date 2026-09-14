package hub

import (
	"database/sql"
	"errors"
	"fmt"
	"sync/atomic"
)

// ErrInsufficientFunds means the tenant's prepaid balance cannot cover the
// hold another job needs. Like the quota it is refused before dispatch, so
// the provider is never asked to spend a credential on a job the buyer
// cannot pay for.
var ErrInsufficientFunds = errors.New("tenant prepaid balance exhausted")

// ErrAccountsNeedCeiling means Accounts was configured without MaxJobMicros.
// The prepaid hold is sized by the per-job ceiling: a job is admitted only
// when the tenant's available balance covers it, and nothing else bounds what
// one job can bill. Without a ceiling there is no hold to take, so enabling
// accounts without one is a construction error, not a runtime surprise.
var ErrAccountsNeedCeiling = errors.New("accounts enabled without MaxJobMicros: the prepaid hold needs a per-job ceiling")

// ErrAccountsBroken means a ledger transaction failed in a way that is not a
// business refusal — the disk is full, the database file is gone, the write
// lock could not be taken. The failed transaction rolled back, so the ledger
// itself is still consistent; what is unknown is whether the Hub can book the
// next charge. Accounting therefore refuses every new hold until the process
// is restarted against a healthy database: fail-closed, the same shape as the
// serve-mode key requirements. A charge whose service was already delivered
// cannot be rolled back, and this refusal is what bounds how far the Hub can
// drift before someone looks.
var ErrAccountsBroken = errors.New("ledger persistence failed; refusing new jobs until restart")

// ErrOrderConflict means an order id was reused for a different charge, or a
// hold or release arrived for an order that has already moved money. One order
// id books exactly one charge; a second, different booking is either a broken
// caller or a double-charge attempt, and neither is booked.
var ErrOrderConflict = errors.New("order already booked with different terms")

// ErrUnknownOrder means a charge or release named an order the ledger has no
// record of. Holds create their order before dispatch, so an unknown order is
// a caller bug: refusing keeps a stray charge from inventing an account.
var ErrUnknownOrder = errors.New("no such order in the ledger")

// Order states. An order is opened held by the admission that reserves its
// hold, and ends in exactly one terminal state.
const (
	// OrderHeld: the hold is frozen and the job is running (or about to).
	OrderHeld = "held"
	// OrderSettled: the job was billed and its hold was consumed.
	OrderSettled = "settled"
	// OrderReleased: the job ended without booking; its hold went back.
	OrderReleased = "released"
	// OrderCharged: the job was billed after its hold had already gone back —
	// the watchdog-closed session shape.
	OrderCharged = "charged"
)

// Account roles. The Hub keeps one table for all three so that a settlement
// writes the debit and both credits in a single transaction.
const (
	roleBuyer    = "buyer"
	roleSeller   = "seller"
	rolePlatform = "platform"

	// platformName is the single platform account's name column.
	platformName = ""
)

// Order is one job's ledger record. ID is the job id the Hub minted before
// dispatch — the same value the provider's receipt carries — and it is the
// transaction id of the charge: quoting it re-reads this record instead of
// booking a second one.
type Order struct {
	ID         string
	Tenant     string
	Provider   string
	State      string
	Hold       uint64
	Buyer      uint64
	Seller     uint64
	Commission uint64
	OpenedAt   int64
	ClosedAt   int64
}

// Booked reports whether money moved for this order.
func (o Order) Booked() bool {
	return o.State == OrderSettled || o.State == OrderCharged
}

// ReconcileReport is the ledger's own audit of itself: the conserved quantity
// read back three ways. Booked is Σ balances recomputed from the accounts;
// Recorded is what the ledger believes it booked; Funded is Σ everything that
// ever entered the ledger from outside. All three are equal when the books add
// up, which is what Balanced reports.
type ReconcileReport struct {
	Booked     uint64
	Recorded   uint64
	Funded     uint64
	Held       uint64
	Accounts   int
	Orders     int
	OpenOrders int
}

// Balanced reports whether the three views of the conserved quantity agree.
func (r ReconcileReport) Balanced() bool {
	return r.Booked == r.Recorded && r.Booked == r.Funded
}

// Accounts is the Hub's durable money ledger: one prepaid balance per buyer
// (tenant), the amount owed to each seller (provider), and the Hub's own
// accumulated commission, all in one SQLite database.
//
// Buyer debt is impossible by construction. Every job takes a hold of exactly
// MaxJobMicros before dispatch (available = balance - held must cover it), a
// settled buyer bill is capped at MaxJobMicros (ErrJobPriceExceeded), and a
// settlement converts the hold into the charge, so balance >= held always
// holds and a settlement can never push the balance below zero. A tenant with
// no money — or less money than one hold — is refused before a provider is
// ever asked to spend a credential.
//
// Seller and platform money moves only as the mirror image of a buyer charge:
// the split is validated to add up (seller + commission == buyer) before any
// balance changes, and again by the orders table's CHECK constraint, so a
// settlement can neither create nor destroy money.
//
// Durability and concurrency: every movement is one transaction against a
// SQLite database in WAL mode. Durability comes from the engine (a commit
// either happened or did not), idempotency from the order id (see Hold and
// Settle), and serialization from the single writer connection (see
// openLedger). There is no process-local money state to lose or to reconcile
// with the disk: balance, held and every order state read back exactly as
// written. How hard a commit is — fsync or not — is the caller's choice at
// open time and defaults to the strictest (see SyncMode).
//
// Multi-node: this type talks to the money through one *sql.DB pair and holds
// nothing of its own, so moving to a shared database later replaces the two
// handles with one pooled connection to a networked server. The schema, the
// transaction bodies and the idempotency keys are what carry the guarantees,
// not the driver.
type Accounts struct {
	path string

	// w is the single writer connection; r is the reader pool.
	w *sql.DB
	r *sql.DB

	// broken latches a failed transaction. Atomic because it is read on the
	// admission path of every request and set only on the way out of a failed
	// write.
	broken atomic.Bool
}

// OpenAccounts opens (or creates) the ledger database at path and seeds it
// with the given balances when it is empty. The seeds apply only on that first
// creation: re-applying them on every start would silently refund a drained
// tenant. The caller learns whether the ledger was fresh so it can explain
// ignored seeds. A malformed seed (empty tenant, zero amount) is a startup
// failure rather than a silently unfunded tenant.
//
// A ledger that does not add up, and a schema written by a newer binary, are
// both startup failures: the process refuses to trade on books it cannot
// trust.
func OpenAccounts(path string, seeds map[string]uint64, opts ...AccountsOption) (*Accounts, bool, error) {
	cfg := accountsConfig{sync: SyncFull}
	for _, opt := range opts {
		opt(&cfg)
	}
	w, r, err := openLedger(path, cfg.sync)
	if err != nil {
		return nil, false, err
	}
	a := &Accounts{path: path, w: w, r: r}
	opened := true
	defer func() {
		if opened {
			a.Close()
		}
	}()

	fresh, err := a.isEmpty()
	if err != nil {
		return nil, false, err
	}
	if fresh {
		if err := a.seed(seeds); err != nil {
			return nil, false, err
		}
	}
	// Holds belong to jobs, and jobs do not survive a process. Whatever the
	// previous process left frozen is released here, journaled, so the log has
	// no hold that nothing will ever close.
	if err := a.releaseOrphans(); err != nil {
		return nil, false, err
	}
	if _, err := a.Reconcile(); err != nil {
		return nil, false, err
	}
	opened = false
	return a, fresh, nil
}

// Close releases both handles. The ledger keeps nothing in memory, so an
// unclosed ledger loses nothing; this exists so a test or a short-lived tool
// can let go of the file.
func (a *Accounts) Close() error {
	var errs []error
	if a.r != nil {
		errs = append(errs, a.r.Close())
	}
	if a.w != nil {
		errs = append(errs, a.w.Close())
	}
	return errors.Join(errs...)
}

// Path reports the database file the ledger is stored in.
func (a *Accounts) Path() string { return a.path }

// isEmpty reports whether the ledger has never booked anything, which is the
// condition for applying the first-boot seeds.
func (a *Accounts) isEmpty() (bool, error) {
	var n int
	if err := a.r.QueryRow(`SELECT (SELECT COUNT(*) FROM journal) + (SELECT COUNT(*) FROM accounts)`).Scan(&n); err != nil {
		return false, fmt.Errorf("read ledger %s: %w", a.path, err)
	}
	return n == 0, nil
}

// refusal marks an error as a request the ledger turned down: the books are
// untouched and the ledger stays healthy, so the Hub keeps serving. It is the
// opposite of latch, and it applies whether the request was refused before a
// transaction was opened or inside one (where the deferred rollback undoes the
// work). What the two shapes share is the answer they give about the ledger's
// ability to keep booking charges.
type refusal struct{ err error }

func (r refusal) Error() string { return r.err.Error() }
func (r refusal) Unwrap() error { return r.err }

func refuse(err error) error { return refusal{err} }

// latch marks the ledger broken and returns the violation. It is for the cases
// where the ledger's own bookkeeping contradicts itself rather than for a
// request that asks for too much: a settlement that is not zero-sum, an amount
// the columns cannot hold, a hold that does not cover the price it was sized
// for, a balance that no longer covers a hold taken from it. Every charge built
// by the same arithmetic will fail the same way, and a Hub that keeps serving
// through that gives away service it can never bill for, so it stops taking
// work until someone looks (see ErrAccountsBroken).
func (a *Accounts) latch(err error) error {
	a.broken.Store(true)
	return err
}

// write runs fn in one immediate transaction on the writer connection.
//
// A refusal is returned to the caller as-is. Any other failure latches the
// ledger broken and is reported as ErrAccountsBroken: the transaction rolled
// back, so no money moved, but the Hub can no longer promise it can book the
// next charge.
func (a *Accounts) write(fn func(*sql.Tx) error) error {
	if a.broken.Load() {
		return ErrAccountsBroken
	}
	err := func() error {
		tx, err := a.w.Begin()
		if err != nil {
			return err
		}
		// A no-op once Commit has run, which is what makes this safe to defer.
		defer tx.Rollback() //nolint:errcheck
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit()
	}()
	var ref refusal
	if errors.As(err, &ref) {
		return ref.err
	}
	if err != nil {
		a.broken.Store(true)
		return fmt.Errorf("%w: %w", ErrAccountsBroken, err)
	}
	return nil
}

// account is one row of the accounts table, in the int64 the database stores.
type account struct {
	role    string
	name    string
	balance int64
	held    int64
}

// getAccount reads one account. The second result reports whether the account
// exists at all, which the money rules treat differently from a zero balance:
// an account comes into being with its first money, and a tenant that has
// never been funded cannot hold anything.
func getAccount(q queryer, role, name string) (account, bool, error) {
	row := account{role: role, name: name}
	err := q.QueryRow(`SELECT balance, held FROM accounts WHERE role = ? AND name = ?`, role, name).
		Scan(&row.balance, &row.held)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return account{role: role, name: name}, false, nil
	case err != nil:
		return account{role: role, name: name}, false, fmt.Errorf("read %s account %q: %w", role, name, err)
	}
	return row, true, nil
}

// setBalance writes an account's balance, creating the account if this is the
// first money that has ever landed on it. The value is absolute, computed by
// the caller from a read taken inside the same transaction, so no read-modify-
// write window exists outside the lock.
func setBalance(tx *sql.Tx, role, name string, balance int64) error {
	_, err := tx.Exec(`INSERT INTO accounts (role, name, balance, held) VALUES (?, ?, ?, 0)
		ON CONFLICT (role, name) DO UPDATE SET balance = excluded.balance`, role, name, balance)
	if err != nil {
		return fmt.Errorf("write %s account %q: %w", role, name, err)
	}
	return nil
}

// Hold reserves amount for one job and opens the order that names it.
//
// orderID is the transaction id of the charge this job may become: the Hub
// mints it before dispatch, so the hold, the charge and the provider's receipt
// all name the same job. Holding the same order id twice with the same terms
// is a no-op, which makes the admission path safe to retry; holding an order
// that already moved money is refused.
//
// A tenant with no balance is refused without creating any state, so tenant
// names an attacker invents cannot grow the tables.
func (a *Accounts) Hold(orderID, tenant string, amount uint64) error {
	if orderID == "" {
		return a.latch(errors.New("ledger hold with an empty order id: a charge must be nameable"))
	}
	if tenant == "" {
		return a.latch(errors.New("ledger hold with an empty tenant"))
	}
	if amount == 0 {
		return a.latch(errors.New("ledger hold of zero reserves nothing"))
	}
	hold, err := toMicros(amount)
	if err != nil {
		return a.latch(err)
	}

	return a.write(func(tx *sql.Tx) error {
		order, found, err := getOrder(tx, orderID)
		if err != nil {
			return err
		}
		if found {
			if order.state == OrderHeld && order.tenant == tenant && order.hold == hold {
				return nil // the same admission again: already held
			}
			return refuse(fmt.Errorf("%w: order %s is %s (tenant %q, hold %d)", ErrOrderConflict, orderID, order.state, order.tenant, order.hold))
		}

		buyer, funded, err := getAccount(tx, roleBuyer, tenant)
		if err != nil {
			return err
		}
		if !funded {
			return refuse(fmt.Errorf("%w: tenant %q has no funded account", ErrInsufficientFunds, tenant))
		}
		available := buyer.balance - buyer.held
		if available < hold {
			return refuse(fmt.Errorf("%w: tenant %q has %d available, needs %d", ErrInsufficientFunds, tenant, available, hold))
		}

		now := nowMicros()
		if _, err := tx.Exec(`INSERT INTO orders (id, tenant, state, hold, opened_at) VALUES (?, ?, ?, ?, ?)`,
			orderID, tenant, OrderHeld, hold, now); err != nil {
			return fmt.Errorf("open order %s: %w", orderID, err)
		}
		if _, err := tx.Exec(`UPDATE accounts SET held = ? WHERE role = ? AND name = ?`,
			buyer.held+hold, roleBuyer, tenant); err != nil {
			return fmt.Errorf("reserve hold for order %s: %w", orderID, err)
		}
		return insertJournal(tx, journalEntry{kind: kindHold, tx: orderID, tenant: tenant, hold: hold, at: now})
	})
}

// Settle books the buyer's charge for one order and credits the seller and the
// platform in a single transaction.
//
// The order's own state decides what the charge does to the buyer's reservation:
// a held order consumes its hold, while an order whose hold has already gone
// back — the watchdog-closed session shape, where the connection close released
// the hold before the truncated receipt was priced — is billed directly, because
// the service was delivered and the charge is still due. The order row is also
// the idempotency record: settling it again with the same numbers books
// nothing and returns nil, so a retried or replayed charge cannot be applied
// twice, and settling it with different numbers is refused.
//
// The split must add up (seller + commission == buyer) and a price above the
// hold is a Hub bug (the per-job ceiling is what sized the hold); both are
// refused rather than booked, because a settlement must be exactly zero-sum.
func (a *Accounts) Settle(orderID, provider string, buyer, seller, commission uint64) error {
	if orderID == "" {
		return a.latch(errors.New("settlement with an empty order id"))
	}
	if err := validSplit(provider, buyer, seller, commission); err != nil {
		return a.latch(err)
	}
	bill, charge, fee, err := toMicros3(buyer, seller, commission)
	if err != nil {
		return a.latch(err)
	}

	return a.write(func(tx *sql.Tx) error {
		order, found, err := getOrder(tx, orderID)
		if err != nil {
			return err
		}
		if !found {
			return refuse(fmt.Errorf("%w: %s", ErrUnknownOrder, orderID))
		}
		switch order.state {
		case OrderSettled, OrderCharged:
			if order.provider == provider && order.buyer == bill && order.seller == charge && order.commission == fee {
				return nil // the same charge again: already booked
			}
			return refuse(fmt.Errorf("%w: order %s already booked buyer %d (seller %d + commission %d) from provider %q",
				ErrOrderConflict, orderID, order.buyer, order.seller, order.commission, order.provider))
		case OrderHeld:
			if bill > order.hold {
				// The per-job ceiling is what sized the hold, so a bill above it
				// means the pricing path and the admission path disagree.
				return a.latch(fmt.Errorf("settle for order %s: buyer %d exceeds hold %d", orderID, buyer, order.hold))
			}
		}

		buyerAcct, funded, err := getAccount(tx, roleBuyer, order.tenant)
		if err != nil {
			return err
		}
		if !funded {
			return refuse(fmt.Errorf("%w: tenant %q has no funded account", ErrUnknownOrder, order.tenant))
		}
		held := buyerAcct.held
		if order.state == OrderHeld {
			// A held order's bill was bounded by its own reservation, so the
			// balance has to cover it: the hold was only granted against an
			// available balance and nothing else can have spent it. Failing
			// either check means the frozen amount and the balance have
			// drifted apart.
			if buyerAcct.balance < bill {
				return a.latch(fmt.Errorf("settle for order %s: tenant %q balance %d cannot cover buyer %d",
					orderID, order.tenant, buyerAcct.balance, buyer))
			}
			held -= order.holdMicros()
			if held < 0 {
				return a.latch(fmt.Errorf("settle for order %s: tenant %q held %d does not cover hold %d",
					orderID, order.tenant, buyerAcct.held, order.hold))
			}
		} else if buyerAcct.balance-buyerAcct.held < bill {
			// This order's hold was released before it was priced, so the
			// money it reserved may already have been reserved and spent by
			// another job. That is the known "delivered but unbillable" race,
			// and it is a refusal rather than a broken ledger: nothing about
			// the books is inconsistent, the tenant is simply out of money.
			//
			// The check is against the available balance (balance - held),
			// not the balance itself: the charge leaves held untouched, and a
			// bill the balance could cover but the available could not would
			// push held above balance, tripping the accounts CHECK and
			// latching a ledger that is not actually broken.
			return refuse(fmt.Errorf("%w: tenant %q has %d available, cannot cover buyer %d for the released order %s",
				ErrInsufficientFunds, order.tenant, buyerAcct.balance-buyerAcct.held, buyer, orderID))
		}

		sellerAcct, _, err := getAccount(tx, roleSeller, provider)
		if err != nil {
			return err
		}
		platformAcct, _, err := getAccount(tx, rolePlatform, platformName)
		if err != nil {
			return err
		}
		// The seller is paid exactly its rate card, and the Hub keeps exactly
		// what the buyer was billed on top of it. Both additions are checked
		// here, on the same numbers the journal then records: saturating
		// arithmetic is for the observation counters, not for a balance that
		// has to keep matching the journal that produced it.
		newSeller, ok := addChecked(microsOf(sellerAcct.balance), seller)
		if !ok {
			return a.latch(fmt.Errorf("settle for order %s: seller %q balance %d + %d overflows",
				orderID, provider, sellerAcct.balance, seller))
		}
		newPlatform, ok := addChecked(microsOf(platformAcct.balance), commission)
		if !ok {
			return a.latch(fmt.Errorf("settle for order %s: platform balance %d + %d overflows",
				orderID, platformAcct.balance, commission))
		}
		// A settlement moves money between the three roles and nothing else,
		// so the conserved quantity is untouched by construction: the debit
		// equals the two credits (validSplit) and nothing new is created.

		now := nowMicros()
		// Balance and hold move together in one statement: they are the two
		// halves of the buyer's side of the settlement, and updating them
		// separately would pass through a state where the frozen amount no
		// longer fits inside the balance it was frozen from.
		if _, err := tx.Exec(`UPDATE accounts SET balance = ?, held = ? WHERE role = ? AND name = ?`,
			buyerAcct.balance-bill, held, roleBuyer, order.tenant); err != nil {
			return fmt.Errorf("settle order %s: %w", orderID, err)
		}
		if err := setBalance(tx, roleSeller, provider, int64(newSeller)); err != nil {
			return err
		}
		if err := setBalance(tx, rolePlatform, platformName, int64(newPlatform)); err != nil {
			return err
		}

		state := OrderSettled
		if order.state != OrderHeld {
			// The hold was already released, so this charge bills the buyer
			// directly instead of consuming a reservation.
			state = OrderCharged
		}
		if _, err := tx.Exec(`UPDATE orders SET state = ?, provider = ?, buyer = ?, seller = ?, commission = ?, closed_at = ? WHERE id = ?`,
			state, provider, bill, charge, fee, now, orderID); err != nil {
			return fmt.Errorf("close order %s: %w", orderID, err)
		}
		kind := kindSettle
		if state == OrderCharged {
			kind = kindCharge
		}
		return insertJournal(tx, journalEntry{
			kind: kind, tx: orderID, tenant: order.tenant, provider: provider,
			hold: order.holdMicros(), buyer: bill, seller: charge, commission: fee, at: now,
		})
	})
}

// Release gives back an unsettled hold and closes the order.
//
// It is idempotent (releasing twice is a no-op) and it never refunds money
// that already moved: an order that settled or charged keeps its money even if
// a late release arrives, because the settle and the release of one job race
// by construction — the deferred release of a settled job, and the connection
// close of a session whose watchdog already fired, both land here. The order's
// terminal state is what decides, not the caller's bookkeeping.
func (a *Accounts) Release(orderID string) error {
	if orderID == "" {
		return errors.New("release with an empty order id")
	}
	return a.write(func(tx *sql.Tx) error {
		order, found, err := getOrder(tx, orderID)
		if err != nil {
			return err
		}
		if !found {
			return refuse(fmt.Errorf("%w: %s", ErrUnknownOrder, orderID))
		}
		if order.state != OrderHeld {
			return nil
		}
		buyer, funded, err := getAccount(tx, roleBuyer, order.tenant)
		if err != nil {
			return err
		}
		if !funded {
			return refuse(fmt.Errorf("%w: tenant %q has no funded account", ErrUnknownOrder, order.tenant))
		}
		held := buyer.held - order.holdMicros()
		if held < 0 {
			return a.latch(fmt.Errorf("release order %s: tenant %q held %d does not cover hold %d",
				orderID, order.tenant, buyer.held, order.hold))
		}
		now := nowMicros()
		if _, err := tx.Exec(`UPDATE accounts SET held = ? WHERE role = ? AND name = ?`, held, roleBuyer, order.tenant); err != nil {
			return fmt.Errorf("release hold for order %s: %w", orderID, err)
		}
		if _, err := tx.Exec(`UPDATE orders SET state = ?, closed_at = ? WHERE id = ?`, OrderReleased, now, orderID); err != nil {
			return fmt.Errorf("close order %s: %w", orderID, err)
		}
		return insertJournal(tx, journalEntry{kind: kindRelease, tx: orderID, tenant: order.tenant, hold: order.holdMicros(), at: now})
	})
}

// Available reports what the tenant can still spend: balance minus holds. A
// tenant that has never been funded has 0, without an account being created.
func (a *Accounts) Available(tenant string) (uint64, error) {
	row, found, err := getAccount(a.r, roleBuyer, tenant)
	if err != nil {
		return 0, err
	}
	if !found || row.held >= row.balance {
		return 0, nil
	}
	return uint64(row.balance - row.held), nil
}

// SellerBalance reports what the Hub owes one provider: every settled charge
// that provider earned since the ledger was created.
func (a *Accounts) SellerBalance(provider string) (uint64, error) {
	return a.balanceOf(roleSeller, provider)
}

// PlatformBalance reports the Hub's own cumulative commission.
func (a *Accounts) PlatformBalance() (uint64, error) {
	return a.balanceOf(rolePlatform, platformName)
}

func (a *Accounts) balanceOf(role, name string) (uint64, error) {
	row, found, err := getAccount(a.r, role, name)
	if err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	return microsOf(row.balance), nil
}

// Order reads one order back by its id. This is the idempotent query a payment
// module needs before it asks for anything: it says whether the charge under
// that transaction id has already been booked.
func (a *Accounts) Order(orderID string) (Order, error) {
	order, found, err := getOrder(a.r, orderID)
	if err != nil {
		return Order{}, err
	}
	if !found {
		return Order{}, fmt.Errorf("%w: %s", ErrUnknownOrder, orderID)
	}
	return order.order(), nil
}

// Reconcile checks the ledger against itself, reading the conserved quantity
// three ways: the sum of every account balance, the total the ledger believes
// it booked, and the sum of everything that ever entered from outside. It also
// reports holds still frozen and how many orders are open.
//
// The report is returned even when the books do not add up, so an operator can
// see by how much; the error is the fail-closed signal.
func (a *Accounts) Reconcile() (ReconcileReport, error) {
	var report ReconcileReport
	row := a.r.QueryRow(`SELECT
		(SELECT COALESCE(SUM(balance), 0) FROM accounts),
		(SELECT COALESCE(SUM(held), 0) FROM accounts),
		(SELECT COUNT(*) FROM accounts),
		(SELECT COUNT(*) FROM orders),
		(SELECT COUNT(*) FROM orders WHERE state = 'held')`)
	if err := row.Scan(&report.Booked, &report.Held, &report.Accounts, &report.Orders, &report.OpenOrders); err != nil {
		return report, fmt.Errorf("read ledger %s: %w", a.path, err)
	}
	if err := a.r.QueryRow(`SELECT COALESCE(SUM(funded), 0) FROM journal`).Scan(&report.Funded); err != nil {
		return report, fmt.Errorf("read ledger journal %s: %w", a.path, err)
	}
	var recorded sql.NullInt64
	if err := a.r.QueryRow(`SELECT booked FROM ledger_state WHERE id = 1`).Scan(&recorded); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return report, fmt.Errorf("read ledger state %s: %w", a.path, err)
	}
	report.Recorded = microsOf(recorded.Int64)
	if !report.Balanced() {
		return report, fmt.Errorf("ledger %s does not conserve: balances sum to %d, the ledger recorded %d and %d entered from outside",
			a.path, report.Booked, report.Recorded, report.Funded)
	}
	return report, nil
}

// releaseOrphans releases every hold left frozen by a previous process. A hold
// exists only while its job runs, jobs die with the process, so anything still
// held at startup belongs to a job that will never finish. The release is
// journaled like any other, so the log never keeps a hold that nothing closes
// and a later audit can see when the money went back.
func (a *Accounts) releaseOrphans() error {
	var open int
	if err := a.r.QueryRow(`SELECT COUNT(*) FROM orders WHERE state = ?`, OrderHeld).Scan(&open); err != nil {
		return fmt.Errorf("read open orders %s: %w", a.path, err)
	}
	if open == 0 {
		return nil
	}
	return a.write(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, tenant, hold FROM orders WHERE state = ? ORDER BY opened_at`, OrderHeld)
		if err != nil {
			return fmt.Errorf("read open orders: %w", err)
		}
		type orphan struct {
			id     string
			tenant string
			hold   int64
		}
		var orphans []orphan
		for rows.Next() {
			var o orphan
			if err := rows.Scan(&o.id, &o.tenant, &o.hold); err != nil {
				rows.Close()
				return fmt.Errorf("read open orders: %w", err)
			}
			orphans = append(orphans, o)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("read open orders: %w", err)
		}
		// The rows must be closed before the updates below: a transaction has
		// one connection, and an open result set holds it.
		rows.Close()

		now := nowMicros()
		for _, o := range orphans {
			if _, err := tx.Exec(`UPDATE orders SET state = ?, closed_at = ? WHERE id = ?`, OrderReleased, now, o.id); err != nil {
				return fmt.Errorf("release orphaned order %s: %w", o.id, err)
			}
			if _, err := tx.Exec(`UPDATE accounts SET held = held - ? WHERE role = ? AND name = ?`, o.hold, roleBuyer, o.tenant); err != nil {
				return fmt.Errorf("release orphaned hold for order %s: %w", o.id, err)
			}
			if err := insertJournal(tx, journalEntry{kind: kindRelease, tx: o.id, tenant: o.tenant, hold: o.hold, at: now}); err != nil {
				return err
			}
		}
		return nil
	})
}

// toMicros3 converts a settlement's three amounts to the columns' int64.
func toMicros3(buyer, seller, commission uint64) (bill, charge, fee int64, err error) {
	if bill, err = toMicros(buyer); err != nil {
		return
	}
	if charge, err = toMicros(seller); err != nil {
		return
	}
	fee, err = toMicros(commission)
	return
}

// validSplit checks that a settlement is exactly zero-sum across the three
// roles and that there is a provider to credit. A mismatch is a Hub bug (the
// buyer bill is built as charged + commission), so it must refuse the whole
// settlement rather than move money that does not reconcile.
func validSplit(provider string, buyer, seller, commission uint64) error {
	if provider == "" {
		return errors.New("settlement with an empty provider: the seller credit would have no account")
	}
	total, ok := addChecked(seller, commission)
	if !ok {
		return fmt.Errorf("settlement split overflows: seller %d + commission %d", seller, commission)
	}
	if total != buyer {
		return fmt.Errorf("settlement split does not add up: seller %d + commission %d != buyer %d", seller, commission, buyer)
	}
	return nil
}
