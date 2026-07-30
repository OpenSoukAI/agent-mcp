package main

import (
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// validChargeInput returns a signChargeInput with every field set to something that would pass
// its own check, so each guard test below can zero out exactly one field and know that field
// alone is what triggers the rejection.
func validChargeInput() signChargeInput {
	return signChargeInput{
		TxHash:           "0x" + strings.Repeat("ab", 32),
		AttributionToken: "AA", // decodes fine as base64url; guards run before it's used anyway
		BuyerAgentID:     "7",
		ChainID:          84532,
		SplitRouterAddr:  "0x2222222222222222222222222222222222222222",
	}
}

// TestHandleSignCharge_RejectsZeroChainID pins the REF-218 guard converting a silent chainId=0
// (e.g. from a stale caller still on the retired 'tempoChainId' field) into a loud, named error —
// this guard is the central deliverable of REF-218's agent-mcp side, and had no coverage before
// this test.
func TestHandleSignCharge_RejectsZeroChainID(t *testing.T) {
	in := validChargeInput()
	in.ChainID = 0
	_, _, err := handleSignCharge(nil, nil, in)
	if err == nil {
		t.Fatal("expected error for chainId == 0, got nil")
	}
	if !strings.Contains(err.Error(), "tempoChainId") {
		t.Errorf("error does not name the retired field 'tempoChainId' to help a stale caller: %v", err)
	}
}

// TestHandleSignCharge_RejectsEmptySplitRouterAddr covers the empty-string path distinctly from
// the zero-address path below — they reach the guard's OR condition differently.
func TestHandleSignCharge_RejectsEmptySplitRouterAddr(t *testing.T) {
	in := validChargeInput()
	in.SplitRouterAddr = ""
	_, _, err := handleSignCharge(nil, nil, in)
	if err == nil {
		t.Fatal("expected error for empty splitRouterAddr, got nil")
	}
	if !strings.Contains(err.Error(), "splitRouterMppAddr") {
		t.Errorf("error does not name the retired field 'splitRouterMppAddr' to help a stale caller: %v", err)
	}
}

// TestHandleSignCharge_RejectsZeroSplitRouterAddr covers the zero-address path (a well-formed hex
// string that resolves to common.Address{}), distinct from the empty-string case above.
func TestHandleSignCharge_RejectsZeroSplitRouterAddr(t *testing.T) {
	in := validChargeInput()
	in.SplitRouterAddr = "0x0000000000000000000000000000000000000000"
	_, _, err := handleSignCharge(nil, nil, in)
	if err == nil {
		t.Fatal("expected error for zero-address splitRouterAddr, got nil")
	}
	if !strings.Contains(err.Error(), "splitRouterMppAddr") {
		t.Errorf("error does not name the retired field 'splitRouterMppAddr' to help a stale caller: %v", err)
	}
}

// TestComputeChargeDigest_CrossRepoParityVector_REF218 is the frozen cross-repo digest-parity
// vector (REF-218), mirrored byte-for-byte from backend/internal/signing/charge_commitment_test.go
// TestChargeCommitment_CrossRepoParityVector_REF218. backend ChargeDigest and agent-mcp
// computeChargeDigest MUST agree — if they diverge, every buyer charge commitment fails at
// recover with no useful diagnostic. Keep these literals identical in both repos.
func TestComputeChargeDigest_CrossRepoParityVector_REF218(t *testing.T) {
	payer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	paymentRef := [32]byte{0xaa}
	buyerAgentID := big.NewInt(7)
	attributionTokenHash := [32]byte{0xbb}
	chainID := int64(84532) // Base Sepolia
	verifyingContract := common.HexToAddress("0x2222222222222222222222222222222222222222")

	d, err := computeChargeDigest(payer, paymentRef, buyerAgentID, attributionTokenHash, chainID, verifyingContract)
	if err != nil {
		t.Fatalf("computeChargeDigest: %v", err)
	}
	// Frozen from the first green cross-repo run (backend + agent-mcp agreed). Do NOT hand-adjust
	// this to make a future change pass — a mismatch here means the two repos have diverged.
	const want = "a9ca0fe88657be00dddc6296ed3fc22e21837a6d57b8d6f07d67e9f067c2a85b"
	if got := common.Bytes2Hex(d); got != want {
		t.Fatalf("REF-218 cross-repo parity vector drift vs backend: got %s want %s", got, want)
	}
}

// TestComputeChargeDigest_Vector locks this signer's charge digest to the backend's pinned vector
// (internal/signing/charge_commitment_test.go TestChargeDigest_Vector). Same inputs MUST yield the
// same digest, or the buyer signature won't recover at POST /mpp/charge.
func TestComputeChargeDigest_Vector(t *testing.T) {
	payer := common.HexToAddress("0x1111111111111111111111111111111111111111")
	verifying := common.HexToAddress("0x2222222222222222222222222222222222222222")
	var ref, th [32]byte
	ref[0], th[0] = 0x01, 0x02

	d, err := computeChargeDigest(payer, ref, big.NewInt(7), th, 42431, verifying)
	if err != nil {
		t.Fatalf("computeChargeDigest: %v", err)
	}
	const want = "cbc98da9ed5dae2543d613b9767cc52f6cb6f004e4b2251a11f933877e3b84b3"
	if got := common.Bytes2Hex(d); got != want {
		t.Fatalf("charge digest parity drift vs backend: got %s want %s", got, want)
	}
}
