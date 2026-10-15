package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixedIntentMarkPayload() intentMarkCommitmentPayload {
	return intentMarkCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerIntentAccess",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: intentMarkCommitmentMessage{
			AgentID:  "7",
			IntentID: "01890a5d-ac96-774b-bcce-b302099a8057",
			Result:   "escrow#42",
			Nonce:    "0x" + strings.Repeat("cd", 32),
			Expiry:   "1893456000",
		},
	}
}

func TestIntentMarkTypeString_MatchesBackend(t *testing.T) {
	const want = "IntentMarkCommitment(uint256 agentId,string intentId,string result,bytes32 nonce,uint256 expiry)"
	if intentMarkCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", intentMarkCommitmentTypeString, want)
	}
}

func TestSignIntentMark_RoundTrip(t *testing.T) {
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

	p := fixedIntentMarkPayload()
	_, out, err := handleSignIntentMark(nil, nil, signIntentMarkInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignIntentMark: %v", err)
	}
	digest, err := computeIntentMarkDigest(p)
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

// Changing intentId or result must change the digest — proves both string
// members are bound into the struct hash (not dropped).
func TestSignIntentMark_BindsIntentIDAndResult(t *testing.T) {
	base := fixedIntentMarkPayload()
	d0, _ := computeIntentMarkDigest(base)

	pID := fixedIntentMarkPayload()
	pID.Message.IntentID = "different-intent-id"
	dID, _ := computeIntentMarkDigest(pID)
	if hex.EncodeToString(d0) == hex.EncodeToString(dID) {
		t.Fatal("digest unchanged when intentId changed — intentId not bound")
	}

	pRes := fixedIntentMarkPayload()
	pRes.Message.Result = "escrow#99"
	dRes, _ := computeIntentMarkDigest(pRes)
	if hex.EncodeToString(d0) == hex.EncodeToString(dRes) {
		t.Fatal("digest unchanged when result changed — result not bound")
	}
}

// Empty result is a valid signed value.
func TestSignIntentMark_EmptyResultOK(t *testing.T) {
	p := fixedIntentMarkPayload()
	p.Message.Result = ""
	if _, err := computeIntentMarkDigest(p); err != nil {
		t.Fatalf("empty result should be valid: %v", err)
	}
}
