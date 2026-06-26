package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestReviewCashbackCommitmentTypeString pins the exact type string. It MUST stay
// byte-identical to the backend's reviewCashbackCommitmentTypeString — a divergence
// silently breaks recovery in the backend.
func TestReviewCashbackCommitmentTypeString(t *testing.T) {
	const want = "ReviewCashbackCommitment(uint256 agentId,uint256 reviewId,uint16 cashbackOfCommissionBps,bytes32 nonce,uint256 expiry)"
	if reviewCashbackCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got: %s\nwant: %s", reviewCashbackCommitmentTypeString, want)
	}
}

func newReviewCashbackPayload() reviewCashbackCommitmentPayload {
	return reviewCashbackCommitmentPayload{
		Domain: commitmentDomain{
			Name:              reviewCashbackDomainName,
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
		},
		Message: reviewCashbackCommitmentMessage{
			AgentID:                 "7",
			ReviewID:                "42",
			CashbackOfCommissionBps: "1500",
			Nonce:                   "0x" + strings.Repeat("ab", 32),
			Expiry:                  "9999999999",
		},
	}
}

func TestComputeReviewCashbackDigestRoundTrip(t *testing.T) {
	const testKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privKey, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	digest, err := computeReviewCashbackDigest(newReviewCashbackPayload())
	if err != nil {
		t.Fatalf("computeReviewCashbackDigest: %v", err)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pubKeyBytes, err := crypto.Ecrecover(digest, sig)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pubKey); got != wantAddr {
		t.Errorf("address mismatch: got %s, want %s", got.Hex(), wantAddr.Hex())
	}
}

// TestHandleSignReviewCashbackOutput verifies the handler returns a 0x-prefixed 65-byte
// signature whose v=27/28 offset, once stripped, recovers the signer (as the backend does).
func TestHandleSignReviewCashbackOutput(t *testing.T) {
	const testKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privKey, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	ks, err := parseKeystore("", "0x"+testKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	signerKeys = ks

	payload := newReviewCashbackPayload()
	_, out, err := handleSignReviewCashback(nil, nil, signReviewCashbackInput{Commitment: payload})
	if err != nil {
		t.Fatalf("handleSignReviewCashback: %v", err)
	}
	if !strings.HasPrefix(out.Signature, "0x") {
		t.Fatalf("signature missing 0x prefix: %s", out.Signature)
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil {
		t.Fatalf("decode signature hex: %v", err)
	}
	if len(sigBytes) != 65 {
		t.Fatalf("signature length %d, want 65", len(sigBytes))
	}

	normSig := make([]byte, 65)
	copy(normSig, sigBytes)
	if normSig[64] >= 27 {
		normSig[64] -= 27
	}
	digest, err := computeReviewCashbackDigest(payload)
	if err != nil {
		t.Fatalf("computeReviewCashbackDigest: %v", err)
	}
	pubKeyBytes, err := crypto.Ecrecover(digest, normSig)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pubKey); got != wantAddr {
		t.Errorf("recovered address %s, want %s", got.Hex(), wantAddr.Hex())
	}
}
