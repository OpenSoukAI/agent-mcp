package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestSettleFallback_ABIPack asserts the extended commissionEscrowABI packs
// triggerSettleFallback(escrowId) to the on-chain selector + arg. A typo'd ABI string is
// the highest-probability defect in this tool, and it would otherwise only surface as an
// opaque revert against a live chain.
func TestSettleFallback_ABIPack(t *testing.T) {
	escrowID := big.NewInt(42)

	data, err := commissionEscrowABI.Pack("triggerSettleFallback", escrowID)
	if err != nil {
		t.Fatalf("Pack triggerSettleFallback: %v", err)
	}
	if len(data) != 4+32 {
		t.Fatalf("calldata len = %d, want 36", len(data))
	}
	wantSel := crypto.Keccak256([]byte("triggerSettleFallback(uint256)"))[:4]
	if got, want := hex.EncodeToString(data[:4]), hex.EncodeToString(wantSel); got != want {
		t.Fatalf("selector = %s, want %s", got, want)
	}
	args, err := commissionEscrowABI.Methods["triggerSettleFallback"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(escrowID) != 0 {
		t.Fatalf("unpacked arg = %v, want 42", args[0])
	}
}

// TestSettleFallback_ParseInputs asserts decimal-string inputs parse and reject garbage.
func TestSettleFallback_ParseInputs(t *testing.T) {
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "42", AgentID: "7"}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "nope", AgentID: "7"}); err == nil {
		t.Fatal("expected error on bad escrow_id")
	}
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "42", AgentID: ""}); err == nil {
		t.Fatal("expected error on empty agent_id")
	}
}

// TestFallbackEligibility pins the contract's own gate: eligibleAt = windowEnd + 10 days,
// and the comparison is NOT strict (the contract reverts only while now < eligibleAt), so
// exactly-at-eligibleAt must be eligible. Testing this as a pure function is the only way
// to cover it without a chain.
func TestFallbackEligibility(t *testing.T) {
	const windowEnd = 1_000_000
	const tenDays = 10 * 24 * 60 * 60

	at, ok := fallbackEligibility(windowEnd, windowEnd+tenDays-1)
	if at != windowEnd+tenDays {
		t.Fatalf("eligibleAt = %d, want %d", at, windowEnd+tenDays)
	}
	if ok {
		t.Fatal("one second early must NOT be eligible")
	}
	if _, ok := fallbackEligibility(windowEnd, windowEnd+tenDays); !ok {
		t.Fatal("exactly at eligibleAt must be eligible")
	}
	if _, ok := fallbackEligibility(windowEnd, windowEnd+tenDays+1); !ok {
		t.Fatal("past eligibleAt must be eligible")
	}
}

// TestDecodeSettleFallbackRevert maps each custom error this tool can hit to a non-empty
// message. TooEarly carries three args; only the selector is matched, so the body is padding.
func TestDecodeSettleFallbackRevert(t *testing.T) {
	for _, sig := range []string{
		"AlreadySettled(uint256)",
		"EscrowNotFound(uint256)",
		"TooEarly(uint256,uint256,uint256)",
		"EnforcedPause()",
	} {
		sel := crypto.Keccak256([]byte(sig))[:4]
		data := append(append([]byte{}, sel...), make([]byte, 96)...)
		msg, ok := decodeSettleFallbackRevertData(data)
		if !ok || msg == "" {
			t.Fatalf("%s: expected a decoded message, got ok=%v msg=%q", sig, ok, msg)
		}
	}
	if _, ok := decodeSettleFallbackRevertData([]byte{0x01, 0x02}); ok {
		t.Fatal("short data must not decode")
	}
}

// TestDecodeEscrowWindowEndAndState packs a SYNTHETIC getEscrow return tuple (all 13
// EscrowRecord fields, declaration order) and asserts windowEnd and state decode from the
// right words. Fixture contract: every one of the 13 words gets a DISTINCT value (numeric
// fields distinct from every other numeric field; address/bytes32 are separately-typed words
// that can't collide with a numeric read), so ANY single-word slip in either direction on
// EITHER windowEnd (word 9) or state (word 11) reads a different word's value and fails an
// assertion — it cannot coincidentally pass by reading a same-valued neighbour. In particular:
// windowEnd's neighbours are depositTimestamp (word 8) and productType (word 10); state's
// neighbours are productType (word 10) and cashbackReleased (word 12, ABI-encoded 0 for
// false) — productType=2 and cashbackReleased=false were chosen specifically so neither equals
// wantState=1. No network call.
func TestDecodeEscrowWindowEndAndState(t *testing.T) {
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

	windowEnd, state, err := decodeEscrowWindowEndAndState(packed)
	if err != nil {
		t.Fatalf("decodeEscrowWindowEndAndState: %v", err)
	}
	if windowEnd != wantWindowEnd {
		t.Fatalf("windowEnd = %d, want %d", windowEnd, wantWindowEnd)
	}
	if state != wantState {
		t.Fatalf("state = %d, want %d", state, wantState)
	}

	if _, _, err := decodeEscrowWindowEndAndState(packed[:383]); err == nil {
		t.Fatal("expected error on short data (383 bytes, one short of the 384 needed)")
	}
}

// TestSettleFallback_KeyLookupNormalizesAgentID proves the handler resolves the signing key
// by the canonical (trimmed) agent_id. The keystore has NO fallback key, so a missed lookup
// is visibly a "no key for agent" error rather than a silent wrong-key signature.
func TestSettleFallback_KeyLookupNormalizesAgentID(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("BASE_RPC_URL", "") // handler stops here, AFTER a successful KeyFor
	_, _, err = handleTriggerSettleFallback(context.Background(), nil, settleFallbackInput{AgentID: " 7 ", EscrowID: "1"})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	if strings.Contains(err.Error(), "no key for agent") {
		t.Fatalf("whitespace agent_id missed the keystore entry (key lookup not normalized): %v", err)
	}
}
