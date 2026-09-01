package main

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

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
		msg, ok := settleFallbackRevertTable.lookupData(data)
		if !ok || msg == "" {
			t.Fatalf("%s: expected a decoded message, got ok=%v msg=%q", sig, ok, msg)
		}
	}
	if _, ok := settleFallbackRevertTable.lookupData([]byte{0x01, 0x02}); ok {
		t.Fatal("short data must not decode")
	}
}

// fakeEscrowRevertErr implements dataError so decodeSettleFallbackRevert can be exercised
// without a live RPC error. Used to lock in the preflight-getEscrow decode path added in the
// whole-branch review fix wave (M1): a nonexistent escrow_id now decodes EscrowNotFound at the
// getEscrow CallContract error instead of only at the later Transact error, which was
// unreachable because getEscrow itself reverts first for a nonexistent id.
type fakeEscrowRevertErr struct{ data string }

func (e fakeEscrowRevertErr) Error() string          { return "execution reverted" }
func (e fakeEscrowRevertErr) ErrorData() interface{} { return e.data }

// TestDecodeSettleFallbackRevert_FromError proves decodeSettleFallbackRevert (the err-based
// wrapper used at both the getEscrow preflight and the Transact call site) correctly unwraps a
// go-ethereum-shaped revert error, and that a plain error (no revert data) does not decode.
func TestDecodeSettleFallbackRevert_FromError(t *testing.T) {
	sel := crypto.Keccak256([]byte("EscrowNotFound(uint256)"))[:4]
	data := append(append([]byte{}, sel...), make([]byte, 32)...)
	fake := fakeEscrowRevertErr{data: "0x" + hex.EncodeToString(data)}

	msg, ok := settleFallbackRevertTable.lookupErr(fake)
	if !ok || msg == "" {
		t.Fatalf("expected a decoded message from a fake revert error, got ok=%v msg=%q", ok, msg)
	}

	if _, ok := settleFallbackRevertTable.lookupErr(errors.New("boom")); ok {
		t.Fatal("a plain error with no revert data must not decode")
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

	t.Setenv("COMMISSION_ESCROW_ADDRESS", "0x000000000000000000000000000000000000dEaD") // config is read before the dial
	t.Setenv("BASE_RPC_URL", "")                                                        // handler stops here, AFTER a successful KeyFor
	_, _, err = handleTriggerSettleFallback(context.Background(), nil, settleFallbackInput{AgentID: " 7 ", EscrowID: "1"})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	if strings.Contains(err.Error(), "no key for agent") {
		t.Fatalf("whitespace agent_id missed the keystore entry (key lookup not normalized): %v", err)
	}
}
