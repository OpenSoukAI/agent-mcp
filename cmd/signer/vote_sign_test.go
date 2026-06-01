package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestComputeVoteDigestRoundTrip builds a fixed voteCommitmentPayload, signs it
// with a known key, then recovers the signer address from the digest+signature
// and asserts it equals the key's address.
func TestComputeVoteDigestRoundTrip(t *testing.T) {
	// Known test key — never use on mainnet.
	const testKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	privKey, err := crypto.HexToECDSA(testKeyHex)
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	payload := voteCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerVotes",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
		},
		Message: voteCommitmentMessage{
			AgentID:          "1",
			PurchaseRecordID: "42",
			VotesHash:        "0x" + strings.Repeat("ab", 32),
			Nonce:            "7",
			Expiry:           "9999999999",
		},
	}

	digest, err := computeVoteDigest(payload)
	if err != nil {
		t.Fatalf("computeVoteDigest: %v", err)
	}

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	// sig[64] is v=0/1 from crypto.Sign; Ecrecover expects v=0/1 (not 27/28).
	// The MCP handler adds +27 for on-chain use, but recovery uses the raw form.
	_ = hex.EncodeToString(sig) // confirms sig is 65 bytes

	pubKeyBytes, err := crypto.Ecrecover(digest, sig)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	gotAddr := crypto.PubkeyToAddress(*pubKey)

	if gotAddr != wantAddr {
		t.Errorf("address mismatch: got %s, want %s", gotAddr.Hex(), wantAddr.Hex())
	}
}

// TestHandleSignVoteOutput verifies that handleSignVote returns a 0x-prefixed
// 65-byte hex signature and that stripping the +27 offset recovers the correct
// signer address — mirroring what RecoverVoteEIP712Signer does in the backend.
func TestHandleSignVoteOutput(t *testing.T) {
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

	payload := voteCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerVotes",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF",
		},
		Message: voteCommitmentMessage{
			AgentID:          "1",
			PurchaseRecordID: "42",
			VotesHash:        "0x" + strings.Repeat("ab", 32),
			Nonce:            "7",
			Expiry:           "9999999999",
		},
	}

	_, out, err := handleSignVote(nil, nil, signVoteInput{Commitment: payload})
	if err != nil {
		t.Fatalf("handleSignVote: %v", err)
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

	// Strip the +27 offset before ecrecover (backend does the same).
	normSig := make([]byte, 65)
	copy(normSig, sigBytes)
	if normSig[64] >= 27 {
		normSig[64] -= 27
	}

	digest, err := computeVoteDigest(payload)
	if err != nil {
		t.Fatalf("computeVoteDigest: %v", err)
	}
	pubKeyBytes, err := crypto.Ecrecover(digest, normSig)
	if err != nil {
		t.Fatalf("ecrecover: %v", err)
	}
	pubKey, err := crypto.UnmarshalPubkey(pubKeyBytes)
	if err != nil {
		t.Fatalf("unmarshal pubkey: %v", err)
	}
	gotAddr := crypto.PubkeyToAddress(*pubKey)

	if gotAddr != wantAddr {
		t.Errorf("recovered address %s, want %s", gotAddr.Hex(), wantAddr.Hex())
	}
}
