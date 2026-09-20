package hub

import (
	"fmt"

	"github.com/reclaimprotocol/reclaim-tee/tokenhive/proof"
)

// amounts is what one priced job moves: what the provider earned under its own
// card, the Hub's cut, and what the buyer is billed. The three travel together
// because the ledger and the outcome record them together, and because buyer is
// charged + commission by construction rather than by three callers agreeing.
type amounts struct {
	provider   uint64
	commission uint64
	buyer      uint64
}

// price turns one receipt into what it is worth, over the bytes the Hub
// actually relayed.
//
// relayedBytes, not the receipt's own response count, is what the volume rate
// applies to: the TEE rejects whole chunks that cross MaxResponseBytes, so the
// delivered prefix can end below the cap while ResponseBytes counts everything
// the provider sent, and billing against either number would charge the buyer
// for bytes never received. Callers pass the length of the chunk stream they
// verified against the receipt's hash, which is the one number attested by
// construction.
func (h *Hub) price(card RateCard, model string, relayedBytes uint64, r proof.Receipt) (amounts, error) {
	charged, err := Price(card, model, relayedBytes, r)
	if err != nil {
		return amounts{}, err
	}
	commission, err := h.commission.CommissionOn(charged)
	if err != nil {
		return amounts{}, err
	}
	buyer, ok := addChecked(charged, commission)
	if !ok {
		return amounts{}, fmt.Errorf("%w: charged %d plus commission %d", ErrPriceOverflow, charged, commission)
	}
	return amounts{provider: charged, commission: commission, buyer: buyer}, nil
}

// book is the single settlement path for every job the Hub charges for,
// request or session: keep the receipt where the provider can audit it, refuse
// to move money for a price over the Hub's ceiling, refuse to book the same job
// twice, and only then record the money.
//
// The ordering is load-bearing. The receipt is stored before the ledger
// settles, so money books only when the provider's audit record is durable: a
// store failure means the exchange did not happen as far as the books are
// concerned, and the buyer is not charged for an answer whose receipt was never
// kept. And the ceiling is checked before anything moves, because a job priced
// above it really happened — its receipt is kept for the provider — but nothing
// is charged, commissioned or settled.
//
// withheld is the test seam for a Hub that hides an execution: the receipt is
// settled but deliberately never stored, so the provider can prove the gap.
// The returned flag reports whether the receipt reached the store.
//
// It is checked before the ceiling because it is an instruction about the store
// rather than a pricing decision: a job that is both over the ceiling and named
// as hidden must still not reach the store, or the seam would stop being able
// to hide the one receipt a test asked it to hide.
func (h *Hub) book(tenant, provider string, receipt proof.SignedReceipt, amt amounts, withheld bool) (bool, error) {
	stored := !withheld
	switch {
	case withheld:
		// Deliberately unstored, not a failed store: removing the provider's
		// audit record is the whole point of this seam.
	case h.maxJob > 0 && amt.buyer > h.maxJob:
		if err := h.store.Put(provider, receipt); err != nil {
			return false, fmt.Errorf("store receipt: %w", err)
		}
		return true, fmt.Errorf("%w: buyer %d exceeds %d", ErrJobPriceExceeded, amt.buyer, h.maxJob)
	default:
		// The receipt must be durable before the ledger books money. The
		// ledger is the record of money that moved, and money must not move
		// without the provider's audit record behind it; a store failure means
		// the exchange did not happen as far as the books are concerned, and
		// the caller still gets the priced outcome to report what would have
		// been charged.
		if err := h.store.Put(provider, receipt); err != nil {
			return false, fmt.Errorf("store receipt: %w", err)
		}
	}
	if !h.claimSettlement(receipt.Receipt.JobID) {
		return stored, fmt.Errorf("%w: job %x", ErrDuplicateSettlement, receipt.Receipt.JobID)
	}
	h.ledger.NoteSettled(provider, amt.provider)
	h.ledger.NoteCommission(provider, amt.commission)
	h.chargeTenant(tenant, amt.buyer)
	return stored, nil
}
