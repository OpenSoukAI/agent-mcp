package main

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

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
