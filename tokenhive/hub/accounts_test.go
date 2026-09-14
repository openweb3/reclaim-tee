package hub

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/jobs"
	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

const (
	testHold = 2_000_000 // the per-job ceiling every test here holds against
	testBill = 1_000_000 // what the default test rate card bills per job
)

// ledgerPath is where a test ledger lives: the database file the Hub would be
// pointed at with -accounts.
func ledgerPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "ledger.db")
}

func openTestAccounts(t *testing.T, seeds map[string]uint64) (*Accounts, string) {
	t.Helper()
	path := ledgerPath(t)
	acc, _, err := OpenAccounts(path, seeds)
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	t.Cleanup(func() { _ = acc.Close() })
	return acc, path
}

// oid names one order in a test. A real order id is the hex of the Hub's job
// id; the ledger only requires that an order is nameable.
func oid(name string) string { return "order-" + name }

// available reports a tenant's spendable balance, failing the test on a read
// error (a ledger that cannot answer a balance query is broken).
func available(t *testing.T, acc *Accounts, tenant string) uint64 {
	t.Helper()
	got, err := acc.Available(tenant)
	if err != nil {
		t.Fatalf("Available(%q): %v", tenant, err)
	}
	return got
}

func sellerBalance(t *testing.T, acc *Accounts, provider string) uint64 {
	t.Helper()
	got, err := acc.SellerBalance(provider)
	if err != nil {
		t.Fatalf("SellerBalance(%q): %v", provider, err)
	}
	return got
}

func platformBalance(t *testing.T, acc *Accounts) uint64 {
	t.Helper()
	got, err := acc.PlatformBalance()
	if err != nil {
		t.Fatalf("PlatformBalance: %v", err)
	}
	return got
}

func orderState(t *testing.T, acc *Accounts, orderID string) Order {
	t.Helper()
	order, err := acc.Order(orderID)
	if err != nil {
		t.Fatalf("Order(%q): %v", orderID, err)
	}
	return order
}

// mustReconcile asserts the books add up: every balance in the accounts table,
// the total the ledger recorded, and everything that ever entered from outside
// must be the same number.
func mustReconcile(t *testing.T, acc *Accounts) ReconcileReport {
	t.Helper()
	report, err := acc.Reconcile()
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	return report
}

func TestAccountsSeedOnlyOnFirstCreate(t *testing.T) {
	path := ledgerPath(t)
	acc, fresh, err := OpenAccounts(path, map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	defer acc.Close()
	if !fresh {
		t.Fatalf("a first create must report fresh")
	}
	if got := available(t, acc, "alice"); got != 100 {
		t.Fatalf("available = %d, want 100", got)
	}
	again, fresh, err := OpenAccounts(path, map[string]uint64{"alice": 100})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if fresh {
		t.Fatalf("an existing ledger must not report fresh: re-seeding would refund a drained tenant")
	}
	if got := available(t, again, "alice"); got != 100 {
		t.Fatalf("available after reopen = %d, want 100 (the seed must not be re-applied)", got)
	}
}

func TestSeedIsRecordedAsFunding(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 5_000_000})
	report := mustReconcile(t, acc)
	if report.Booked != 5_000_000 || report.Funded != 5_000_000 {
		t.Fatalf("after seeding: booked %d, funded %d, want 5000000 both (money enters the ledger, it is not invented in it)",
			report.Booked, report.Funded)
	}
}

func TestHoldGatesOnBalance(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold(oid("nobody"), "nobody", testHold); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("unfunded tenant hold err = %v, want ErrInsufficientFunds", err)
	}
	if got := available(t, acc, "nobody"); got != 0 {
		t.Fatalf("a refused hold must not create state for the tenant")
	}
	if _, err := acc.Order(oid("nobody")); !errors.Is(err, ErrUnknownOrder) {
		t.Fatalf("a refused hold must not open an order, got %v", err)
	}
	if err := acc.Hold(oid("first"), "alice", testHold); err != nil {
		t.Fatalf("hold within balance: %v", err)
	}
	if err := acc.Hold(oid("second"), "alice", 1); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("second hold with the balance fully held err = %v, want ErrInsufficientFunds", err)
	}
	if err := acc.Release(oid("first")); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := acc.Hold(oid("third"), "alice", testHold); err != nil {
		t.Fatalf("hold after release: %v", err)
	}
}

// TestHoldIsIdempotentPerOrder pins the admission contract: the order id is
// what makes an admission safe to retry, and it must not be usable to reserve
// the same money twice or to reopen a finished order.
func TestHoldIsIdempotentPerOrder(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold(oid("a"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Hold(oid("a"), "alice", testHold); err != nil {
		t.Fatalf("replaying the same hold must be a no-op, got %v", err)
	}
	if got := available(t, acc, "alice"); got != 0 {
		t.Fatalf("available after a replayed hold = %d, want 0 (the reservation must not double)", got)
	}
	if err := acc.Hold(oid("a"), "alice", 1); !errors.Is(err, ErrOrderConflict) {
		t.Fatalf("reusing an order id for a different reservation err = %v, want ErrOrderConflict", err)
	}
	if err := acc.Release(oid("a")); err != nil {
		t.Fatalf("release: %v", err)
	}
	if err := acc.Hold(oid("a"), "alice", testHold); !errors.Is(err, ErrOrderConflict) {
		t.Fatalf("holding a released order again err = %v, want ErrOrderConflict (one order, one admission)", err)
	}
}

func TestSettleConvertsHoldToCharge(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	// balance 3M - 1M = 2M, nothing held: a new job must admit again.
	if got := available(t, acc, "alice"); got != 2*testBill {
		t.Fatalf("available after settle = %d, want %d", got, 2*testBill)
	}
	order := orderState(t, acc, oid("job"))
	if order.State != OrderSettled || order.Buyer != testBill || order.Seller != testBill {
		t.Fatalf("settled order = %+v, want state %s with buyer and seller %d", order, OrderSettled, testBill)
	}
	if !order.Booked() {
		t.Fatalf("a settled order must report itself booked")
	}

	if err := acc.Settle(oid("job"), testProvider, testHold+1, testHold+1, 0); !errors.Is(err, ErrOrderConflict) {
		t.Fatalf("booking a different charge under a settled order err = %v, want ErrOrderConflict", err)
	}
	if got := available(t, acc, "alice"); got != 2*testBill {
		t.Fatalf("a refused settle must not move money: available = %d", got)
	}
}

// TestSettleIsIdempotentPerOrder is the durable half of the double-charge
// guarantee: the receipt is the caller's evidence, but the order row is what
// decides. Booking the same numbers twice books nothing the second time.
func TestSettleIsIdempotentPerOrder(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	if got := available(t, acc, "alice"); got != 2*testBill {
		t.Fatalf("available after three identical settlements = %d, want %d (one charge, not three)", got, 2*testBill)
	}
	if got := sellerBalance(t, acc, testProvider); got != testBill {
		t.Fatalf("seller balance after three identical settlements = %d, want %d", got, testBill)
	}
	mustReconcile(t, acc)
}

func TestSettleRejectsAPriceAboveTheHold(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("job"), testProvider, testHold+1, testHold+1, 0); err == nil {
		t.Fatalf("a price above the hold is a Hub bug and must be refused")
	}
	if got := available(t, acc, "alice"); got != 3*testBill-testHold {
		t.Fatalf("available after a refused settle = %d, want the hold still in place", got)
	}
	if orderState(t, acc, oid("job")).State != OrderHeld {
		t.Fatalf("a refused settle must leave the order held")
	}
	// Pricing kept producing bills the hold it took does not cover: the ceiling
	// that sized the hold and the price that came back disagree, so the Hub
	// must not keep dispatching jobs it cannot bill.
	if err := acc.Hold(oid("next"), "alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after a bill above its hold err = %v, want ErrAccountsBroken", err)
	}
}

// TestSettleAfterReleaseChargesDirectly covers the watchdog-closed session: the
// connection close gives the hold back before the truncated receipt is priced,
// and the charge is still due.
func TestSettleAfterReleaseChargesDirectly(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Release(oid("job")); err != nil {
		t.Fatalf("release: %v", err)
	}
	if got := available(t, acc, "alice"); got != testHold {
		t.Fatalf("available after release = %d, want the whole balance back", got)
	}
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("charge after release: %v", err)
	}
	if got := available(t, acc, "alice"); got != testHold-testBill {
		t.Fatalf("available after charge = %d, want %d", got, testHold-testBill)
	}
	if got := orderState(t, acc, oid("job")).State; got != OrderCharged {
		t.Fatalf("order state = %s, want %s", got, OrderCharged)
	}
	// Releasing after the charge must not refund money that already moved.
	if err := acc.Release(oid("job")); err != nil {
		t.Fatalf("release after charge: %v", err)
	}
	if got := available(t, acc, "alice"); got != testHold-testBill {
		t.Fatalf("a release after a charge refunded it: available = %d, want %d", got, testHold-testBill)
	}
}

// TestSettleAfterReleaseRefusesWhenOtherHoldsLeaveNoAvailable is the regression
// for the charged path's check: a released order's charge leaves the tenant's
// other holds untouched, so it must be gated on available (balance - held), not
// on balance. A bill the balance could cover but the available could not used
// to trip the accounts CHECK and latch the ledger broken; it must refuse the
// charge and keep the ledger healthy.
func TestSettleAfterReleaseRefusesWhenOtherHoldsLeaveNoAvailable(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 1000})

	if err := acc.Hold(oid("closed"), "alice", 300); err != nil {
		t.Fatalf("hold the session the watchdog will close: %v", err)
	}
	if err := acc.Release(oid("closed")); err != nil {
		t.Fatalf("release the closed session: %v", err)
	}
	for _, id := range []string{"run1", "run2", "run3"} {
		if err := acc.Hold(oid(id), "alice", 300); err != nil {
			t.Fatalf("hold %s: %v", id, err)
		}
	}
	// balance 1000, held 900, available 100: a 200 charge on the released
	// order fits the balance but not the available.
	if err := acc.Settle(oid("closed"), testProvider, 200, 200, 0); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("charge on the released order err = %v, want ErrInsufficientFunds (not a broken ledger)", err)
	}
	if got := available(t, acc, "alice"); got != 100 {
		t.Fatalf("a refused charge moved money: available = %d, want 100", got)
	}
	// A refusal is not a latch: the ledger keeps taking new holds.
	if err := acc.Hold(oid("run4"), "alice", 100); err != nil {
		t.Fatalf("a refused charge latched the ledger: hold after refusal: %v", err)
	}
	if err := acc.Release(oid("run4")); err != nil {
		t.Fatalf("release run4: %v", err)
	}
	mustReconcile(t, acc)
}

func TestReleaseIsIdempotent(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})
	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := acc.Release(oid("job")); err != nil {
			t.Fatalf("release %d: %v", i, err)
		}
	}
	if got := available(t, acc, "alice"); got != testHold {
		t.Fatalf("available after three releases = %d, want %d (the hold returns once)", got, testHold)
	}
	mustReconcile(t, acc)
}

func TestChargeOnAnUnknownOrderIsRefused(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})
	if err := acc.Settle(oid("ghost"), testProvider, testBill, testBill, 0); !errors.Is(err, ErrUnknownOrder) {
		t.Fatalf("charge on an order that was never held err = %v, want ErrUnknownOrder", err)
	}
	if err := acc.Release(oid("ghost")); !errors.Is(err, ErrUnknownOrder) {
		t.Fatalf("release of an order that was never held err = %v, want ErrUnknownOrder", err)
	}
	if got := sellerBalance(t, acc, testProvider); got != 0 {
		t.Fatalf("a refused charge credited the seller %d", got)
	}
}

// TestAccountsPersistAcrossReopen is the durability claim: every balance and
// every order is in the database, and a fresh process reads back exactly what
// the previous one booked.
func TestAccountsPersistAcrossReopen(t *testing.T) {
	path := ledgerPath(t)
	acc, _, err := OpenAccounts(path, map[string]uint64{"alice": 3 * testBill})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	// An unsettled hold, whose job dies with this process.
	if err := acc.Hold(oid("open"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	// The settle is on disk and the orphaned hold was released at startup: the
	// job it belonged to died with the previous process, and leaving it frozen
	// would strand the money forever.
	if got := available(t, again, "alice"); got != 2*testBill {
		t.Fatalf("available after reopen = %d, want %d (settled charge kept, orphaned hold released)", got, 2*testBill)
	}
	if got := orderState(t, again, oid("job")); got.State != OrderSettled || got.Buyer != testBill {
		t.Fatalf("settled order after reopen = %+v", got)
	}
	if got := orderState(t, again, oid("open")).State; got != OrderReleased {
		t.Fatalf("orphaned order state after reopen = %s, want %s", got, OrderReleased)
	}
	if got := sellerBalance(t, again, testProvider); got != testBill {
		t.Fatalf("seller balance after reopen = %d, want %d", got, testBill)
	}
	if report := mustReconcile(t, again); report.OpenOrders != 0 {
		t.Fatalf("open orders after reopen = %d, want 0", report.OpenOrders)
	}
}

// TestSettleSurvivesRestartAsTheIdempotencyRecord is the guarantee the in-memory
// dedup cannot make: a charge replayed by a process that never saw the first
// one is still refused, because the order id is on disk.
func TestSettleSurvivesRestartAsTheIdempotencyRecord(t *testing.T) {
	path := ledgerPath(t)
	acc, _, err := OpenAccounts(path, map[string]uint64{"alice": 3 * testBill})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	// The replay the restarted process sees: same order, same numbers.
	if err := again.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("replaying a booked charge must be a no-op, got %v", err)
	}
	if got := available(t, again, "alice"); got != 2*testBill {
		t.Fatalf("available after a replayed charge = %d, want %d (charged once)", got, 2*testBill)
	}
	if got := sellerBalance(t, again, testProvider); got != testBill {
		t.Fatalf("seller balance after a replayed charge = %d, want %d", got, testBill)
	}
}

// TestConcurrentHoldsCannotOverspend is what a single writer connection buys:
// money is reserved atomically, so any number of simultaneous admissions can
// never reserve more than the balance.
func TestConcurrentHoldsCannotOverspend(t *testing.T) {
	const slots = 8
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": slots * testBill})

	var wg sync.WaitGroup
	results := make([]error, 2*slots)
	for i := 0; i < 2*slots; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Every attempt wants a full hold, so only `slots` of them can
			// have one.
			results[i] = acc.Hold(fmt.Sprintf("order-%d", i), "alice", testBill)
		}(i)
	}
	wg.Wait()

	granted := 0
	for i, err := range results {
		switch {
		case err == nil:
			granted++
		case errors.Is(err, ErrInsufficientFunds):
		default:
			t.Fatalf("hold %d: unexpected error %v", i, err)
		}
	}
	if granted != slots {
		t.Fatalf("granted %d holds of %d slots' worth of balance, want exactly %d", granted, slots, slots)
	}
	if got := available(t, acc, "alice"); got != 0 {
		t.Fatalf("available after %d full holds = %d, want 0", granted, got)
	}
	report := mustReconcile(t, acc)
	if report.Held != slots*testBill {
		t.Fatalf("held = %d, want %d", report.Held, slots*testBill)
	}
	if report.OpenOrders != slots {
		t.Fatalf("open orders = %d, want %d", report.OpenOrders, slots)
	}
}

// TestConcurrentReplayChargesOnce is the "no double charge" requirement under
// contention: many callers holding the same receipt cannot book it twice.
func TestConcurrentReplayChargesOnce(t *testing.T) {
	const callers = 16
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})
	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}

	var wg sync.WaitGroup
	results := make([]error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = acc.Settle(oid("job"), testProvider, testBill, testBill, 0)
		}(i)
	}
	wg.Wait()

	for i, err := range results {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if got := available(t, acc, "alice"); got != 2*testBill {
		t.Fatalf("available after %d concurrent replays = %d, want %d", callers, got, 2*testBill)
	}
	if got := sellerBalance(t, acc, testProvider); got != testBill {
		t.Fatalf("seller balance after %d concurrent replays = %d, want %d", callers, got, testBill)
	}
	mustReconcile(t, acc)
}

func TestBrokenLedgerRefusesNewHolds(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": testHold})

	if err := acc.Hold(oid("a"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	// Close the writer handle: every attempt to begin a transaction fails,
	// which is the shape of a disk error or a database that has gone away.
	if err := acc.w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	if err := acc.Settle(oid("a"), testProvider, testBill, testBill, 0); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("a settle that cannot commit err = %v, want ErrAccountsBroken", err)
	}
	if err := acc.Hold(oid("b"), "alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after a failed write err = %v, want ErrAccountsBroken (fail closed)", err)
	}
}

// TestReconcileDetectsATamperedLedger is the audit path: money changed behind
// the ledger's back is visible, and a ledger that does not add up refuses to
// open at all rather than trading on books it cannot trust.
func TestReconcileDetectsATamperedLedger(t *testing.T) {
	path := ledgerPath(t)
	acc, _, err := OpenAccounts(path, map[string]uint64{"alice": testBill})
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if _, err := acc.w.Exec(`UPDATE accounts SET balance = balance + 1 WHERE role = 'buyer'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	report, err := acc.Reconcile()
	if err == nil {
		t.Fatalf("a ledger whose balances no longer match its own record must not reconcile: %+v", report)
	}
	if report.Balanced() {
		t.Fatalf("report claims to be balanced: %+v", report)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, _, err := OpenAccounts(path, nil); err == nil {
		t.Fatalf("opening a ledger that does not add up must fail")
	}
}

func TestAccountsRequireCeiling(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)
	_, err := New(Config{
		TEE:      &ScriptedTEE{},
		Rates:    ratesTable(map[string]RateCard{}),
		Store:    NewReceiptStore(t.TempDir()),
		Verify:   acceptAll,
		Accounts: acc,
	})
	if !errors.Is(err, ErrAccountsNeedCeiling) {
		t.Fatalf("accounts without MaxJobMicros err = %v, want ErrAccountsNeedCeiling", err)
	}
}

// --- end to end: no money, no service --------------------------------------

func TestPrepaidBalanceGatesDispatch(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"rich": 2 * testHold})
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		return Result{Receipt: makeReceipt(uint64(call), nil, func(r *proof.Receipt) {
			r.Provider = spec.Provider
			r.JobID = spec.JobID
		})}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Accounts: acc, MaxJobMicros: testHold})

	run := func(tenant string) error {
		_, err := h.Execute(context.Background(), tenant, "m", testSpec(testProvider, "m"), nil, nil)
		return err
	}

	if err := run("nobody"); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("unfunded tenant err = %v, want ErrInsufficientFunds", err)
	}
	for i := 0; i < 3; i++ {
		if err := run("rich"); err != nil {
			t.Fatalf("job %d within balance: %v", i, err)
		}
	}
	if got := available(t, acc, "rich"); got != testHold-testBill {
		t.Fatalf("available after three jobs = %d, want %d", got, testHold-testBill)
	}
	// The remaining balance no longer backs one hold: the next job cannot be
	// admitted, so it is refused before dispatch.
	if err := run("rich"); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("drained tenant err = %v, want ErrInsufficientFunds", err)
	}
	if got := available(t, acc, "rich"); got != testHold-testBill {
		t.Fatalf("a refused job must not move money: available = %d", got)
	}
	// The seller side is credited by the same settlement that bills the buyer:
	// three settled jobs, three times the provider's price.
	if got := sellerBalance(t, acc, testProvider); got != 3*testBill {
		t.Fatalf("seller balance across three settled jobs = %d, want %d", got, 3*testBill)
	}
	if got := platformBalance(t, acc); got != 0 {
		t.Fatalf("platform balance with no commission configured = %d, want 0", got)
	}
	report := mustReconcile(t, acc)
	if report.Orders != 3 || report.OpenOrders != 0 {
		t.Fatalf("orders = %d (open %d), want 3 booked and none left holding money", report.Orders, report.OpenOrders)
	}
}

// TestExecuteBooksOneOrderPerJob pins the identity the charge is keyed by: the
// job id the Hub dispatched is the ledger's transaction id, and it is what the
// provider's receipt names too.
func TestExecuteBooksOneOrderPerJob(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})
	var dispatched jobs.Spec
	fake := &ScriptedTEE{Reply: func(call int, spec jobs.Spec) (Result, error) {
		dispatched = spec
		return Result{Receipt: makeReceipt(uint64(call), nil, func(r *proof.Receipt) {
			r.Provider = spec.Provider
			r.JobID = spec.JobID
		})}, nil
	}}
	h := mustHub(t, Config{TEE: fake, Accounts: acc, MaxJobMicros: testHold})

	out, err := h.Execute(context.Background(), "alice", "m", testSpec(testProvider, "m"), nil, nil)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	order, err := acc.Order(orderIDFor(dispatched.JobID))
	if err != nil {
		t.Fatalf("the charge must be findable by the job id the Hub dispatched: %v", err)
	}
	if order.State != OrderSettled || order.Buyer != out.Buyer || order.Seller != out.Charged {
		t.Fatalf("order = %+v, want the settled charge the outcome reports (%+v)", order, out)
	}
	if got := string(order.ID); got != orderIDFor(out.Receipt.Receipt.JobID) {
		t.Fatalf("order id %q does not match the receipt's job id %q", got, orderIDFor(out.Receipt.Receipt.JobID))
	}
}

// --- seller and platform money ---------------------------------------------

// testProviderFee is the seller's share of a testBill job; the rest is the
// Hub's commission. It is deliberately not a round half so a mix-up between
// the two accounts shows up as an exact-number failure.
const testProviderFee = 800_000

func TestSettleCreditsSellerAndPlatform(t *testing.T) {
	acc, path := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	commission := uint64(testBill - testProviderFee)
	if err := acc.Hold(oid("first"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("first"), testProvider, testBill, testProviderFee, commission); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := sellerBalance(t, acc, testProvider); got != testProviderFee {
		t.Fatalf("seller balance = %d, want %d", got, testProviderFee)
	}
	if got := platformBalance(t, acc); got != commission {
		t.Fatalf("platform balance = %d, want %d", got, commission)
	}
	mustReconcile(t, acc)

	// The money must be on disk, not just in memory: reopening is what turns
	// "we recorded it" into "we still owe it" after a restart.
	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if got := sellerBalance(t, again, testProvider); got != testProviderFee {
		t.Fatalf("seller balance after reopen = %d, want %d", got, testProviderFee)
	}
	if got := platformBalance(t, again); got != commission {
		t.Fatalf("platform balance after reopen = %d, want %d", got, commission)
	}

	// The reopen re-derived the conserved total; a further settlement has to
	// clear it as well.
	if err := again.Hold(oid("second"), "alice", testHold); err != nil {
		t.Fatalf("hold after reopen: %v", err)
	}
	if err := again.Settle(oid("second"), testProvider, testBill, testProviderFee, commission); err != nil {
		t.Fatalf("settle after reopen: %v", err)
	}
	if got := sellerBalance(t, again, testProvider); got != 2*testProviderFee {
		t.Fatalf("seller balance after a second settlement = %d, want %d", got, 2*testProviderFee)
	}
	if got := platformBalance(t, again); got != 2*commission {
		t.Fatalf("platform balance after a second settlement = %d, want %d", got, 2*commission)
	}
	if got := available(t, again, "alice"); got != 3*testBill-2*testBill {
		t.Fatalf("buyer balance after two settlements = %d, want %d", got, testBill)
	}
	mustReconcile(t, again)
}

func TestSettleRejectsASplitThatDoesNotAddUp(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	// seller + commission > buyer: booking this would create money out of
	// nothing, so the whole settlement must be refused.
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 1); err == nil {
		t.Fatalf("a split that does not add up must be refused")
	}
	if got := sellerBalance(t, acc, testProvider); got != 0 {
		t.Fatalf("seller balance after a refused split = %d, want 0", got)
	}
	if got := platformBalance(t, acc); got != 0 {
		t.Fatalf("platform balance after a refused split = %d, want 0", got)
	}
	// The hold is still in place: the settlement was rolled back whole.
	if want := uint64(3*testBill - testHold); available(t, acc, "alice") != want {
		t.Fatalf("available after a refused split = %d, want %d", available(t, acc, "alice"), want)
	}
	if got := orderState(t, acc, oid("job")).State; got != OrderHeld {
		t.Fatalf("order state after a refused split = %s, want %s", got, OrderHeld)
	}
	// A split that does not add up is not a request the ledger turned down: it
	// is the Hub's own arithmetic failing, and every charge built the same way
	// will fail the same way. So the ledger stops taking work rather than keep
	// serving requests it can never bill for.
	if err := acc.Hold(oid("next"), "alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("hold after a split that does not add up err = %v, want ErrAccountsBroken", err)
	}
}

func TestSettleRejectsAnEmptyProvider(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testBill})

	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("job"), "", testBill, testBill, 0); err == nil {
		t.Fatalf("a settlement with no provider to credit must be refused")
	}
	if got := available(t, acc, "alice"); got != 3*testBill-testHold {
		t.Fatalf("a refused settlement moved money: available = %d", got)
	}
	if err := acc.Hold(oid("next"), "alice", testHold); !errors.Is(err, ErrAccountsBroken) {
		t.Fatalf("a credit with no account to land on is a Hub bug: err = %v, want ErrAccountsBroken", err)
	}
}

func TestSellerPayablesAccumulatePerProvider(t *testing.T) {
	// Four jobs' worth: each admission needs a full hold available, so the
	// starting balance has to outlast the charges themselves.
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 4 * testBill})

	for i := 0; i < 2; i++ {
		order := fmt.Sprintf("cheap-%d", i)
		if err := acc.Hold(order, "alice", testHold); err != nil {
			t.Fatalf("hold %d: %v", i, err)
		}
		if err := acc.Settle(order, "cheap", testBill, testBill, 0); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	if err := acc.Hold(oid("dear"), "alice", testHold); err != nil {
		t.Fatalf("hold: %v", err)
	}
	if err := acc.Settle(oid("dear"), "dear", testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := sellerBalance(t, acc, "cheap"); got != 2*testBill {
		t.Fatalf("cheap seller balance = %d, want %d", got, 2*testBill)
	}
	if got := sellerBalance(t, acc, "dear"); got != testBill {
		t.Fatalf("dear seller balance = %d, want %d", got, testBill)
	}
	if got := sellerBalance(t, acc, "unknown"); got != 0 {
		t.Fatalf("an unknown provider has no payable, got %d", got)
	}
}

func TestJobSpendSettleAndReleaseAreOnce(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testHold})
	h := mustHub(t, Config{TEE: &ScriptedTEE{}, Accounts: acc, MaxJobMicros: testHold})

	jobID, err := newJobID()
	if err != nil {
		t.Fatalf("newJobID: %v", err)
	}
	spend, err := h.beginJob("alice", jobID)
	if err != nil {
		t.Fatalf("beginJob: %v", err)
	}
	if got := available(t, acc, "alice"); got != 2*testHold {
		t.Fatalf("available under hold = %d, want %d", got, 2*testHold)
	}
	// The normal request shape: settle, then the deferred release. The hold
	// is consumed once, the slot returns, the balance drops once.
	if err := spend.settle(testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	spend.release()
	spend.release()
	if got := available(t, acc, "alice"); got != 3*testHold-testBill {
		t.Fatalf("available after settle+release = %d, want %d", got, 3*testHold-testBill)
	}

	// The watchdog shape: release fires first (hold returned), the charge is
	// still due afterwards.
	jobID2, err := newJobID()
	if err != nil {
		t.Fatalf("newJobID: %v", err)
	}
	spend2, err := h.beginJob("alice", jobID2)
	if err != nil {
		t.Fatalf("beginJob: %v", err)
	}
	spend2.release()
	if got := available(t, acc, "alice"); got != 3*testHold-testBill {
		t.Fatalf("release must return the hold in full: available = %d", got)
	}
	if err := spend2.settle(testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle after release: %v", err)
	}
	if got := available(t, acc, "alice"); got != 3*testHold-2*testBill {
		t.Fatalf("charge after release must bill: available = %d, want %d", got, 3*testHold-2*testBill)
	}
	if h.flight.active("alice") != 0 {
		t.Fatalf("both spends released: the in-flight table must be empty")
	}
	mustReconcile(t, acc)
}

// TestBeginJobRequiresAJobIDThatCanNameAnOrder guards the seam between the Hub
// and the ledger: with billing on, a job that cannot be named cannot be billed,
// and must not be dispatched.
func TestBeginJobRequiresAJobIDThatCanNameAnOrder(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 3 * testHold})
	h := mustHub(t, Config{TEE: &ScriptedTEE{}, Accounts: acc, MaxJobMicros: testHold})

	if _, err := h.beginJob("alice", nil); err == nil {
		t.Fatalf("an admission with no job id must be refused")
	}
	if got := h.flight.active("alice"); got != 0 {
		t.Fatalf("a refused admission left %d in-flight slots held", got)
	}
	if got := available(t, acc, "alice"); got != 3*testHold {
		t.Fatalf("a refused admission moved money: available = %d", got)
	}
}
