package main

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
)

// ── CommissionEscrow.getEscrow return decoding ──────────────────────────────────
//
// Every field of ICommissionEscrow.EscrowRecord is a static ABI type, so getEscrow's
// return is fourteen 32-byte words inline, in declaration order — no offset header, no
// dynamic tail. That makes fixed-slice decoding correct, and it makes an off-by-one-word
// slip silent: the neighbouring word is also a valid-looking number.
//
// This is the single decoder for that tuple. It previously existed twice, decoding
// different subsets at different offsets with different length floors (384 in
// trigger_settle_fallback, 160 in publish_escrow_review), which is two chances for a
// contract-side field reorder to be caught in one place and missed in the other.
//
// Every field is decoded even where no caller reads it yet. The cost is a line per field;
// the alternative is that the next tool needing one more field adds a third partial
// decoder, which is exactly the split this replaces.

// escrowStateSettled is ICommissionEscrow.EscrowState.Settled — the terminal state, set
// once the day-60 batch (or the public fallback) has run.
const escrowStateSettled uint8 = 1

// escrowRecordWords is the number of 32-byte words in the EscrowRecord tuple. A static tuple
// is always exactly this long, so any other length means a different contract layout.
const escrowRecordWords = 14

// onChainEscrow is ICommissionEscrow.EscrowRecord as the signer reads it.
type onChainEscrow struct {
	ReviewerAgentID      *big.Int
	BuyerAgentID         *big.Int
	BuyerWallet          common.Address
	PausedTotalAtDeposit int64
	MerchantID           *big.Int
	ProductID            [32]byte
	HeldBackAmt          *big.Int
	CashbackAmt          *big.Int
	OriginalPurchaseAmt  *big.Int
	DepositTimestamp     int64
	WindowEnd            int64
	ProductType          uint8
	State                uint8 // EscrowState: 0 Holding, 1 Settled
	CashbackReleased     bool
}

// word returns the i-th 32-byte word of an ABI-encoded static tuple.
func word(raw []byte, i int) []byte { return raw[i*32 : (i+1)*32] }

// decodeGetEscrow decodes a CommissionEscrow.getEscrow return blob. Pure and unit-tested
// against a synthetic tuple whose every word holds a distinct value, so a field reorder —
// in a later contract version, or in this file — fails a test instead of silently
// misreading a live chain.
func decodeGetEscrow(raw []byte) (onChainEscrow, error) {
	if len(raw) != escrowRecordWords*32 {
		return onChainEscrow{}, fmt.Errorf(
			"getEscrow returned %d bytes, want %d: contract EscrowRecord layout differs from this signer", len(raw), escrowRecordWords*32)
	}
	var e onChainEscrow
	e.ReviewerAgentID = new(big.Int).SetBytes(word(raw, 0))
	e.BuyerAgentID = new(big.Int).SetBytes(word(raw, 1))
	e.BuyerWallet = common.BytesToAddress(word(raw, 2)) // left-padded to 32 bytes
	e.PausedTotalAtDeposit = new(big.Int).SetBytes(word(raw, 3)).Int64()
	e.MerchantID = new(big.Int).SetBytes(word(raw, 4))
	copy(e.ProductID[:], word(raw, 5))
	e.HeldBackAmt = new(big.Int).SetBytes(word(raw, 6))
	e.CashbackAmt = new(big.Int).SetBytes(word(raw, 7))
	e.OriginalPurchaseAmt = new(big.Int).SetBytes(word(raw, 8))
	e.DepositTimestamp = new(big.Int).SetBytes(word(raw, 9)).Int64()
	e.WindowEnd = new(big.Int).SetBytes(word(raw, 10)).Int64()
	e.ProductType = uint8(new(big.Int).SetBytes(word(raw, 11)).Uint64())
	e.State = uint8(new(big.Int).SetBytes(word(raw, 12)).Uint64())
	e.CashbackReleased = new(big.Int).SetBytes(word(raw, 13)).Sign() != 0
	return e, nil
}
