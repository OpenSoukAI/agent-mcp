package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestBindEscrow_ABIPack asserts the extended commissionEscrowABI packs bind(escrowId, agentId)
// to the correct 4-byte selector + args (the on-chain call the tool sends). Selector for
// bind(uint256,uint256) is 0xcadc1f0a (backend commission_escrow.go).
func TestBindEscrow_ABIPack(t *testing.T) {
	escrowID := big.NewInt(42)
	agentID := big.NewInt(7)

	data, err := commissionEscrowABI.Pack("bind", escrowID, agentID)
	if err != nil {
		t.Fatalf("Pack bind: %v", err)
	}
	if len(data) != 4+32+32 {
		t.Fatalf("calldata len = %d, want 68", len(data))
	}
	// Selector = keccak256("bind(uint256,uint256)")[:4]; assert it matches the on-chain selector.
	wantSel := crypto.Keccak256([]byte("bind(uint256,uint256)"))[:4]
	if got := hex.EncodeToString(data[:4]); got != hex.EncodeToString(wantSel) {
		t.Fatalf("selector = %s, want %s", got, hex.EncodeToString(wantSel))
	}
	if hex.EncodeToString(data[:4]) != "cadc1f0a" {
		t.Fatalf("selector = %s, want cadc1f0a", hex.EncodeToString(data[:4]))
	}
	// Round-trip the args back out.
	args, err := commissionEscrowABI.Methods["bind"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(escrowID) != 0 || args[1].(*big.Int).Cmp(agentID) != 0 {
		t.Fatalf("unpacked args = %v, want [42 7]", args)
	}
}

// TestBindEscrow_ParseInputs asserts decimal-string inputs parse to big.Int and reject garbage.
func TestBindEscrow_ParseInputs(t *testing.T) {
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "42", AgentID: "7"}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "notanumber", AgentID: "7"}); err == nil {
		t.Fatal("expected error on bad escrow_id")
	}
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "42", AgentID: ""}); err == nil {
		t.Fatal("expected error on empty agent_id")
	}
}

// TestBindEscrow_KeyLookupNormalizesAgentID proves handleBindEscrow looks up the signing key by
// the parsed/canonical agent_id (trimmed decimal), not the raw input string. A whitespace-padded
// agent_id must still resolve the keyed entry rather than silently falling back to a different key.
func TestBindEscrow_KeyLookupNormalizesAgentID(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "") // NO fallback
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("COMMISSION_ESCROW_ADDRESS", "0x000000000000000000000000000000000000dEaD") // config is read before the dial
	t.Setenv("BASE_RPC_URL", "")                                                        // handler stops here AFTER a successful KeyFor
	_, _, err = handleBindEscrow(context.Background(), nil, bindEscrowInput{AgentID: " 7 ", EscrowID: "1"})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	// Pre-fix: KeyFor(" 7 ") misses the '7' entry (no fallback) -> "no key for agent" error.
	// Post-fix: KeyFor("7") succeeds -> the error is the later BASE_RPC_URL check.
	if strings.Contains(err.Error(), "no key for agent") {
		t.Fatalf("whitespace agent_id missed the keystore entry (key lookup not normalized): %v", err)
	}
}

// TestDecodeBindRevert maps a known custom-error selector to a friendly message.
func TestDecodeBindRevert(t *testing.T) {
	sel := crypto.Keccak256([]byte("AlreadyBound(uint256)"))[:4]
	// revert data = selector + abi-encoded uint256 arg (value irrelevant to the selector match)
	data := append(append([]byte{}, sel...), make([]byte, 32)...)
	msg, ok := bindRevertTable.lookupData(data)
	if !ok || msg == "" {
		t.Fatalf("expected AlreadyBound decode, got ok=%v msg=%q", ok, msg)
	}
}
