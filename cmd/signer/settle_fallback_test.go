package main

import (
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
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

// TestFallbackEligibility pins the contract's own gate: eligibleAt = windowEnd + 10 days +
// shift (shift = totalPausedSeconds() - pausedTotalAtDeposit, clamped at 0 by the caller), and
// the comparison is NOT strict (the contract reverts only while now < eligibleAt), so
// exactly-at-eligibleAt must be eligible. Testing this as a pure function is the only way to
// cover it without a chain. Run at shift=0 (today's behaviour) and shift=3 days (a pause that
// happened after this escrow's deposit) to prove the shift actually moves the boundary.
func TestFallbackEligibility(t *testing.T) {
	const windowEnd = 1_000_000
	const tenDays = 10 * 24 * 60 * 60

	for _, shift := range []int64{0, 3 * 24 * 60 * 60} {
		want := int64(windowEnd) + tenDays + shift

		at, ok := fallbackEligibility(windowEnd, shift, want-1)
		if at != want {
			t.Fatalf("shift=%d: eligibleAt = %d, want %d", shift, at, want)
		}
		if ok {
			t.Fatalf("shift=%d: one second early must NOT be eligible", shift)
		}
		if _, ok := fallbackEligibility(windowEnd, shift, want); !ok {
			t.Fatalf("shift=%d: exactly at eligibleAt must be eligible", shift)
		}
		if _, ok := fallbackEligibility(windowEnd, shift, want+1); !ok {
			t.Fatalf("shift=%d: past eligibleAt must be eligible", shift)
		}
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

// TestFallbackRefusal_SettledAndCashbackReleased pins today's message: a fully-settled
// escrow (both legs paid) is a terminal refusal, not a retry.
func TestFallbackRefusal_SettledAndCashbackReleased(t *testing.T) {
	escrow := onChainEscrow{State: escrowStateSettled, CashbackReleased: true}
	msg := fallbackRefusal("42", escrow)
	if msg == "" {
		t.Fatal("expected a refusal for Settled && CashbackReleased")
	}
	if !strings.Contains(msg, "already settled") {
		t.Fatalf("refusal message = %q, want it to mention the escrow is already settled", msg)
	}
}

// TestFallbackRefusal_SettledCashbackLegRetry is the Sherlock #11/#19 fix: a Settled escrow
// whose cashback leg previously failed (FallbackCashbackFailed) must be allowed to retry, not
// refused as "already settled".
func TestFallbackRefusal_SettledCashbackLegRetry(t *testing.T) {
	escrow := onChainEscrow{State: escrowStateSettled, CashbackReleased: false}
	if msg := fallbackRefusal("42", escrow); msg != "" {
		t.Fatalf("expected no refusal for Settled && !CashbackReleased (cashback-leg retry), got %q", msg)
	}
}

// TestFallbackRefusal_NotSettled proves the guard is unchanged for an escrow still holding.
func TestFallbackRefusal_NotSettled(t *testing.T) {
	escrow := onChainEscrow{State: 0, CashbackReleased: false}
	if msg := fallbackRefusal("42", escrow); msg != "" {
		t.Fatalf("expected no refusal for a Holding escrow, got %q", msg)
	}
}

// TestDecodeFallbackReceipt_CashbackFailed proves a receipt carrying FallbackSettled (cashback
// leg 0, since it failed) plus FallbackCashbackFailed(escrowId, reviewer, 500) surfaces
// cashback_failed, the reviewer address, and the amount as a decimal string.
func TestDecodeFallbackReceipt_CashbackFailed(t *testing.T) {
	escrowAddr := common.HexToAddress("0x00000000000000000000000000000000000abc")
	reviewer := common.HexToAddress("0x00000000000000000000000000000000000def")

	logs := []*types.Log{
		{
			Address: escrowAddr,
			Topics:  []common.Hash{fallbackSettledTopic, common.BigToHash(big.NewInt(42)), common.BytesToHash(common.HexToAddress("0x01").Bytes())},
			Data:    append(make([]byte, 32), make([]byte, 32)...), // heldBackAmt=0, cashbackAmt=0 (the cashback leg failed)
		},
		{
			Address: escrowAddr,
			Topics:  []common.Hash{fallbackCashbackFailedTopic, common.BigToHash(big.NewInt(42)), common.BytesToHash(reviewer.Bytes())},
			Data:    common.LeftPadBytes(big.NewInt(500).Bytes(), 32),
		},
	}
	// held back = 1000
	copy(logs[0].Data[0:32], common.LeftPadBytes(big.NewInt(1000).Bytes(), 32))

	var out settleFallbackOutput
	decodeFallbackReceipt(&out, logs, escrowAddr)

	if !out.CashbackFailed {
		t.Fatal("expected cashback_failed=true")
	}
	if got := strings.ToLower(out.CashbackFailedReviewer); got != strings.ToLower(reviewer.Hex()) {
		t.Fatalf("CashbackFailedReviewer = %q, want %q", got, reviewer.Hex())
	}
	if out.CashbackFailedAmount != "500" {
		t.Fatalf("CashbackFailedAmount = %q, want %q", out.CashbackFailedAmount, "500")
	}
	if out.HeldBackToTreasury != "1000" {
		t.Fatalf("HeldBackToTreasury = %q, want %q", out.HeldBackToTreasury, "1000")
	}
}

// TestDecodeFallbackReceipt_NoCashbackFailedEvent proves a receipt without the event leaves
// cashback_failed false and the failure fields empty.
func TestDecodeFallbackReceipt_NoCashbackFailedEvent(t *testing.T) {
	escrowAddr := common.HexToAddress("0x00000000000000000000000000000000000abc")
	logs := []*types.Log{
		{
			Address: escrowAddr,
			Topics:  []common.Hash{fallbackSettledTopic, common.BigToHash(big.NewInt(42)), common.BytesToHash(common.HexToAddress("0x01").Bytes())},
			Data:    append(common.LeftPadBytes(big.NewInt(1000).Bytes(), 32), common.LeftPadBytes(big.NewInt(200).Bytes(), 32)...),
		},
	}

	var out settleFallbackOutput
	decodeFallbackReceipt(&out, logs, escrowAddr)

	if out.CashbackFailed {
		t.Fatal("expected cashback_failed=false when the event is absent")
	}
	if out.CashbackFailedReviewer != "" || out.CashbackFailedAmount != "" {
		t.Fatalf("expected empty failure fields, got reviewer=%q amount=%q", out.CashbackFailedReviewer, out.CashbackFailedAmount)
	}
	if out.HeldBackToTreasury != "1000" || out.CashbackToReviewer != "200" {
		t.Fatalf("FallbackSettled decode regressed: held=%q cashback=%q", out.HeldBackToTreasury, out.CashbackToReviewer)
	}
}

// TestDecodeFallbackReceipt_IgnoresLogsFromAnotherAddress proves the escrowAddr filter: a log
// carrying the right topic but from a different contract (e.g. forwarded/replayed in the same
// receipt) must not be decoded into the output (REF-361 review).
func TestDecodeFallbackReceipt_IgnoresLogsFromAnotherAddress(t *testing.T) {
	escrowAddr := common.HexToAddress("0x00000000000000000000000000000000000abc")
	otherAddr := common.HexToAddress("0x00000000000000000000000000000000000999")
	reviewer := common.HexToAddress("0x00000000000000000000000000000000000def")

	logs := []*types.Log{
		{
			Address: otherAddr,
			Topics:  []common.Hash{fallbackSettledTopic, common.BigToHash(big.NewInt(42)), common.BytesToHash(common.HexToAddress("0x01").Bytes())},
			Data:    append(common.LeftPadBytes(big.NewInt(1000).Bytes(), 32), common.LeftPadBytes(big.NewInt(200).Bytes(), 32)...),
		},
		{
			Address: otherAddr,
			Topics:  []common.Hash{fallbackCashbackFailedTopic, common.BigToHash(big.NewInt(42)), common.BytesToHash(reviewer.Bytes())},
			Data:    common.LeftPadBytes(big.NewInt(500).Bytes(), 32),
		},
	}

	var out settleFallbackOutput
	decodeFallbackReceipt(&out, logs, escrowAddr)

	if out.CashbackFailed {
		t.Error("expected cashback_failed=false for a FallbackCashbackFailed log from another address")
	}
	if out.HeldBackToTreasury != "" || out.CashbackToReviewer != "" {
		t.Errorf("expected FallbackSettled from another address to be ignored, got held=%q cashback=%q",
			out.HeldBackToTreasury, out.CashbackToReviewer)
	}
}

// fakeContractCaller is a contractCaller whose CallContract always fails, to prove a
// totalPausedSeconds read failure refuses rather than silently proceeding with shift=0.
type fakeContractCaller struct{ err error }

func (f fakeContractCaller) CallContract(_ context.Context, _ ethereum.CallMsg, _ *big.Int) ([]byte, error) {
	return nil, f.err
}

// TestReadTotalPausedSeconds_ReadFailureRefuses mirrors the existing getEscrow preflight: a
// CallContract error must be returned, not swallowed into a default shift.
func TestReadTotalPausedSeconds_ReadFailureRefuses(t *testing.T) {
	_, err := readTotalPausedSeconds(context.Background(), fakeContractCaller{err: errors.New("rpc boom")}, common.HexToAddress("0x01"))
	if err == nil {
		t.Fatal("expected an error when totalPausedSeconds CallContract fails")
	}
}
