package hub

import (
	"errors"
	"fmt"
	"testing"
)

// These tests pin the contract of the ledger's money-entry seam: the one path
// an external credit takes, whoever drives it (the first-boot seed today, a
// payment module's deposit next). What a payment module leans on is exactly
// what is asserted here — a credit lands once per external transaction, the
// retry of that transaction is idempotent, and a malformed request is refused
// rather than being allowed to stop the Hub from billing anyone.

// mustHold is the probe for "the ledger is still healthy": a refusal that
// latched the ledger would make this fail with ErrAccountsBroken. Each probe
// mints its own job id, so it can be called repeatedly in one test.
func mustHold(t *testing.T, acc *Accounts, tenant string, amount uint64) {
	t.Helper()
	jobID, err := newJobID()
	if err != nil {
		t.Fatalf("newJobID: %v", err)
	}
	orderID := orderIDFor(jobID)
	if err := acc.Hold(orderID, tenant, amount); err != nil {
		t.Fatalf("the ledger must still take work: %v", err)
	}
	if err := acc.Release(orderID); err != nil {
		t.Fatalf("release probe: %v", err)
	}
}

func TestFundCreditsAndConserves(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	for i, amount := range []uint64{500_000, 1_500_000} {
		if err := acc.fund(kindDeposit, fmt.Sprintf("pay-%d", i), "alice", amount); err != nil {
			t.Fatalf("fund %d: %v", amount, err)
		}
	}
	if got := available(t, acc, "alice"); got != 2_000_000 {
		t.Fatalf("available after two deposits = %d, want 2000000", got)
	}
	report := mustReconcile(t, acc)
	if report.Funded != 2_000_000 || report.Booked != 2_000_000 {
		t.Fatalf("after deposits: booked %d, funded %d, want 2000000 both (money comes from outside, it is not invented)",
			report.Booked, report.Funded)
	}
	if report.Accounts != 1 {
		t.Fatalf("accounts = %d, want 1 (a credit creates the buyer's account)", report.Accounts)
	}
}

// TestFundIsIdempotentPerTransaction is the retry a payment module has to be
// able to make: it cannot know whether its first call landed, so calling again
// with the same reference must leave exactly one credit and report success.
func TestFundIsIdempotentPerTransaction(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	for i := 0; i < 3; i++ {
		if err := acc.fund(kindDeposit, "pay-1", "alice", 1_000_000); err != nil {
			t.Fatalf("retry %d of the same deposit: %v", i, err)
		}
	}
	if got := available(t, acc, "alice"); got != 1_000_000 {
		t.Fatalf("available after three identical deposits = %d, want 1000000 (credited once)", got)
	}
	if report := mustReconcile(t, acc); report.Funded != 1_000_000 {
		t.Fatalf("funded = %d, want 1000000", report.Funded)
	}
	mustHold(t, acc, "alice", 1_000_000)
}

// TestFundIdempotencyIsDurable is the same guarantee across a restart: the
// payment module's retry does not have to arrive at the process that booked the
// first attempt.
func TestFundIdempotencyIsDurable(t *testing.T) {
	path := ledgerPath(t)
	acc, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("OpenAccounts: %v", err)
	}
	if err := acc.fund(kindDeposit, "pay-1", "alice", 1_000_000); err != nil {
		t.Fatalf("fund: %v", err)
	}
	if err := acc.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	again, _, err := OpenAccounts(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer again.Close()
	if err := again.fund(kindDeposit, "pay-1", "alice", 1_000_000); err != nil {
		t.Fatalf("retrying the deposit after a restart: %v", err)
	}
	if got := available(t, again, "alice"); got != 1_000_000 {
		t.Fatalf("available after a cross-restart retry = %d, want 1000000", got)
	}
}

func TestFundRejectsTheSameTransactionWithOtherTerms(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	if err := acc.fund(kindDeposit, "pay-1", "alice", 1_000_000); err != nil {
		t.Fatalf("fund: %v", err)
	}
	if err := acc.fund(kindDeposit, "pay-1", "alice", 2_000_000); !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("reusing a payment reference for another amount err = %v, want ErrTransactionConflict", err)
	}
	if err := acc.fund(kindDeposit, "pay-1", "bob", 1_000_000); !errors.Is(err, ErrTransactionConflict) {
		t.Fatalf("reusing a payment reference for another account err = %v, want ErrTransactionConflict", err)
	}
	if got := available(t, acc, "alice"); got != 1_000_000 {
		t.Fatalf("a refused funding moved money: available = %d", got)
	}
	if got := available(t, acc, "bob"); got != 0 {
		t.Fatalf("a refused funding created an account: available = %d", got)
	}
	// A conflict is a refusal, not a broken ledger: the Hub keeps billing.
	mustHold(t, acc, "alice", 1_000_000)
}

// TestFundNamespacesItsIdempotencyKeys pins the reason the journal's unique
// index is on (kind, tx): the same string has to be usable as a payment
// reference and as something else without one being mistaken for a replay of
// the other.
func TestFundNamespacesItsIdempotencyKeys(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	if err := acc.fund(kindDeposit, "same-id", "alice", 1_000_000); err != nil {
		t.Fatalf("fund deposit: %v", err)
	}
	if err := acc.fund(kindSeed, "same-id", "alice", 1_000_000); err != nil {
		t.Fatalf("the same id under another kind must not be read as a replay: %v", err)
	}
	if got := available(t, acc, "alice"); got != 2_000_000 {
		t.Fatalf("available = %d, want 2000000 (both credits applied)", got)
	}
}

// TestFundRefusesMalformedTermsWithoutLatching covers the one entry point that
// takes its terms from outside the process: a bad request is refused, and the
// ledgers of every other tenant keep working.
func TestFundRefusesMalformedTermsWithoutLatching(t *testing.T) {
	acc, _ := openTestAccounts(t, map[string]uint64{"alice": 1_000_000})

	cases := []struct {
		name   string
		txID   string
		tenant string
		amount uint64
	}{
		{name: "no transaction id", tenant: "alice", amount: 1},
		{name: "no account", txID: "pay-1", amount: 1},
		{name: "nothing to credit", txID: "pay-1", tenant: "alice"},
		{name: "an amount the columns cannot hold", txID: "pay-1", tenant: "alice", amount: 1 << 63},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := acc.fund(kindDeposit, tc.txID, tc.tenant, tc.amount)
			if err == nil {
				t.Fatalf("fund(%q, %q, %d) was accepted", tc.txID, tc.tenant, tc.amount)
			}
			if errors.Is(err, ErrAccountsBroken) {
				t.Fatalf("a malformed request must be refused, not stop the Hub: %v", err)
			}
			if got := available(t, acc, "alice"); got != 1_000_000 {
				t.Fatalf("a refused funding moved money: available = %d", got)
			}
			mustHold(t, acc, "alice", 1_000_000)
		})
	}
}

func TestFundedTenantCanSpendImmediately(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	// Before any money, the tenant is refused for having no account at all.
	if err := acc.Hold(oid("early"), "alice", 1); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("unfunded tenant hold err = %v, want ErrInsufficientFunds", err)
	}
	if err := acc.fund(kindDeposit, "pay-1", "alice", testHold); err != nil {
		t.Fatalf("fund: %v", err)
	}
	if err := acc.Hold(oid("job"), "alice", testHold); err != nil {
		t.Fatalf("hold after a deposit: %v", err)
	}
	if err := acc.Settle(oid("job"), testProvider, testBill, testBill, 0); err != nil {
		t.Fatalf("settle: %v", err)
	}
	if got := available(t, acc, "alice"); got != testHold-testBill {
		t.Fatalf("available = %d, want %d", got, testHold-testBill)
	}
	mustReconcile(t, acc)
}

// TestSeedFundsEveryTenantOrNone keeps the genesis atomic: the seeds go through
// the same funding path, so a bad entry has to leave the ledger exactly as
// empty as it was.
func TestSeedFundsEveryTenantOrNone(t *testing.T) {
	acc, _ := openTestAccounts(t, nil)

	if err := acc.seed(map[string]uint64{"alice": 1_000_000, "": 1}); err == nil {
		t.Fatalf("a seed with an unusable tenant name must be refused")
	}
	if got := available(t, acc, "alice"); got != 0 {
		t.Fatalf("a refused seed funded %d", got)
	}
	if report := mustReconcile(t, acc); report.Funded != 0 {
		t.Fatalf("a refused seed changed the conserved total: %+v", report)
	}
	if err := acc.seed(map[string]uint64{"alice": 1_000_000, "bob": 2_000_000}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got := available(t, acc, "alice"); got != 1_000_000 {
		t.Fatalf("alice available = %d, want 1000000", got)
	}
	if got := available(t, acc, "bob"); got != 2_000_000 {
		t.Fatalf("bob available = %d, want 2000000", got)
	}
	mustReconcile(t, acc)
}
