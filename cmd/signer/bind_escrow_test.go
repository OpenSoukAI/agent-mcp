package main

import (
	"encoding/hex"
	"math/big"
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

// TestDecodeBindRevert maps a known custom-error selector to a friendly message.
func TestDecodeBindRevert(t *testing.T) {
	sel := crypto.Keccak256([]byte("AlreadyBound(uint256)"))[:4]
	// revert data = selector + abi-encoded uint256 arg (value irrelevant to the selector match)
	data := append(append([]byte{}, sel...), make([]byte, 32)...)
	msg, ok := decodeBindRevertData(data)
	if !ok || msg == "" {
		t.Fatalf("expected AlreadyBound decode, got ok=%v msg=%q", ok, msg)
	}
}
