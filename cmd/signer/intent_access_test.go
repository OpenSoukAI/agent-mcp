package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixedIntentAccessPayload() intentAccessCommitmentPayload {
	return intentAccessCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerIntentAccess",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: intentAccessCommitmentMessage{
			AgentID: "7",
			Nonce:   "0x" + strings.Repeat("ab", 32),
			Expiry:  "1893456000",
		},
	}
}

func TestIntentAccessTypeString_MatchesBackend(t *testing.T) {
	const want = "IntentAccessCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"
	if intentAccessCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", intentAccessCommitmentTypeString, want)
	}
}

func TestSignIntentAccess_RoundTrip(t *testing.T) {
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "0x000000000000000000000000000000000000aBcD")
	resetAddressCache()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	p := fixedIntentAccessPayload()
	_, out, err := handleSignIntentAccess(nil, nil, signIntentAccessInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignIntentAccess: %v", err)
	}
	digest, err := computeIntentAccessDigest(p)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("sig: err=%v len=%d", err, len(sig))
	}
	recSig := make([]byte, 65)
	copy(recSig, sig)
	recSig[64] -= 27
	pub, err := crypto.SigToPub(digest, recSig)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != want {
		t.Fatalf("recovered %s, want %s", got, want)
	}
}
