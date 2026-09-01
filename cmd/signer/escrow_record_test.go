package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// TestDecodeGetEscrow packs a SYNTHETIC getEscrow return tuple (all 13
// EscrowRecord fields, declaration order) and asserts EVERY field decodes from the right
// word. Fixture contract: every one of the 13 words gets a DISTINCT value (numeric
// fields distinct from every other numeric field; address/bytes32 are separately-typed words
// that can't collide with a numeric read), so ANY single-word slip in either direction on
// ANY field reads a different word's value and fails an assertion — it cannot coincidentally pass by reading a same-valued neighbour. In particular:
// windowEnd's neighbours are depositTimestamp (word 8) and productType (word 10); state's
// neighbours are productType (word 10) and cashbackReleased (word 12, ABI-encoded 0 for
// false) — productType=2 and cashbackReleased=false were chosen specifically so neither equals
// wantState=1. No network call.
func TestDecodeGetEscrow(t *testing.T) {
	mustType := func(t string) abi.Type {
		typ, err := abi.NewType(t, "", nil)
		if err != nil {
			panic(err)
		}
		return typ
	}
	uint128T := mustType("uint128")
	uint40T := mustType("uint40")
	uint8T := mustType("uint8")
	boolT := mustType("bool")

	var productID [32]byte
	copy(productID[:], []byte("synthetic-product-id-32-bytes!!"))
	buyerWallet := common.HexToAddress("0x00000000000000000000000000000000000ABC")

	const (
		reviewerAgentID     = 111
		buyerAgentID        = 222
		merchantID          = 333
		heldBackAmt         = 444
		cashbackAmt         = 555
		originalPurchaseAmt = 666
		depositTimestamp    = 1_690_000_000
		wantWindowEnd       = 1_700_000_000
		productType         = 2     // != wantState (1): guards state's word-10 neighbour
		wantState           = 1     // EscrowState.Settled — the only value the handler branches on
		cashbackReleased    = false // ABI-encodes to word value 0 != wantState (1): guards state's word-12 neighbour
	)

	packed, err := abi.Arguments{
		{Type: abiUint256}, // reviewerAgentId
		{Type: abiUint256}, // buyerAgentId
		{Type: abiAddress}, // buyerWallet
		{Type: abiUint256}, // merchantId
		{Type: abiBytes32}, // productId
		{Type: uint128T},   // heldBackAmt
		{Type: uint128T},   // cashbackAmt
		{Type: uint128T},   // originalPurchaseAmt
		{Type: uint40T},    // depositTimestamp
		{Type: uint40T},    // windowEnd
		{Type: uint8T},     // productType
		{Type: uint8T},     // state
		{Type: boolT},      // cashbackReleased
	}.Pack(
		big.NewInt(reviewerAgentID),
		big.NewInt(buyerAgentID),
		buyerWallet,
		big.NewInt(merchantID),
		productID,
		big.NewInt(heldBackAmt),
		big.NewInt(cashbackAmt),
		big.NewInt(originalPurchaseAmt),
		big.NewInt(depositTimestamp),
		big.NewInt(wantWindowEnd),
		uint8(productType),
		uint8(wantState),
		cashbackReleased,
	)
	if err != nil {
		t.Fatalf("pack synthetic getEscrow tuple: %v", err)
	}

	got, err := decodeGetEscrow(packed)
	if err != nil {
		t.Fatalf("decodeGetEscrow: %v", err)
	}

	// Every field, so a reorder anywhere in the record fails here rather than in whichever
	// tool happens to read the moved field first.
	for _, c := range []struct {
		name      string
		got, want int64
	}{
		{"reviewerAgentId", got.ReviewerAgentID.Int64(), reviewerAgentID},
		{"buyerAgentId", got.BuyerAgentID.Int64(), buyerAgentID},
		{"merchantId", got.MerchantID.Int64(), merchantID},
		{"heldBackAmt", got.HeldBackAmt.Int64(), heldBackAmt},
		{"cashbackAmt", got.CashbackAmt.Int64(), cashbackAmt},
		{"originalPurchaseAmt", got.OriginalPurchaseAmt.Int64(), originalPurchaseAmt},
		{"depositTimestamp", got.DepositTimestamp, depositTimestamp},
		{"windowEnd", got.WindowEnd, wantWindowEnd},
		{"productType", int64(got.ProductType), productType},
		{"state", int64(got.State), wantState},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if got.BuyerWallet != buyerWallet {
		t.Errorf("buyerWallet = %s, want %s", got.BuyerWallet, buyerWallet)
	}
	if got.ProductID != productID {
		t.Errorf("productId = %x, want %x", got.ProductID, productID)
	}
	if got.CashbackReleased != cashbackReleased {
		t.Errorf("cashbackReleased = %v, want %v", got.CashbackReleased, cashbackReleased)
	}

	// One byte short of the full 13-word record. The floor is deliberately the WHOLE record
	// (416 bytes), not just enough words for the fields a given caller reads: a real node
	// always returns all thirteen, so a shorter response is malformed rather than partially
	// trustworthy. This is stricter than the two decoders this replaced (384 and 160).
	if _, err := decodeGetEscrow(packed[:415]); err == nil {
		t.Fatal("expected error on short data (415 bytes, one short of the 416 needed)")
	}
}
