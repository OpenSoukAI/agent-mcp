package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixedIntentSkipPayload() intentSkipCommitmentPayload {
	return intentSkipCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerIntentAccess",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: intentSkipCommitmentMessage{
			AgentID:  "7",
			IntentID: "01890a5d-ac96-774b-bcce-b302099a8057",
			Reason:   "over budget",
			Nonce:    "0x" + strings.Repeat("cd", 32),
			Expiry:   "1893456000",
		},
	}
}

func TestIntentSkipTypeString_MatchesBackend(t *testing.T) {
	const want = "IntentSkipCommitment(uint256 agentId,string intentId,string reason,bytes32 nonce,uint256 expiry)"
	if intentSkipCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", intentSkipCommitmentTypeString, want)
	}
}

func TestSignIntentSkip_RoundTrip(t *testing.T) {
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

	p := fixedIntentSkipPayload()
	_, out, err := handleSignIntentSkip(nil, nil, signIntentSkipInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignIntentSkip: %v", err)
	}
	digest, err := computeIntentSkipDigest(p)
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

// Changing intentId or reason must change the digest — proves both string members are bound.
func TestSignIntentSkip_BindsIntentIDAndReason(t *testing.T) {
	base := fixedIntentSkipPayload()
	d0, _ := computeIntentSkipDigest(base)

	pID := fixedIntentSkipPayload()
	pID.Message.IntentID = "different-intent-id"
	dID, _ := computeIntentSkipDigest(pID)
	if hex.EncodeToString(d0) == hex.EncodeToString(dID) {
		t.Fatal("digest unchanged when intentId changed — intentId not bound")
	}

	pReason := fixedIntentSkipPayload()
	pReason.Message.Reason = "terms drifted"
	dReason, _ := computeIntentSkipDigest(pReason)
	if hex.EncodeToString(d0) == hex.EncodeToString(dReason) {
		t.Fatal("digest unchanged when reason changed — reason not bound")
	}
}

// Byte-parity guard: the skip digest must differ from the mark digest for the same field values —
// distinct type strings ⇒ distinct typehash ⇒ distinct digest, so the two operations are
// domain-separated (a mark sig can never act as a skip and vice-versa).
func TestSignIntentSkip_DomainSeparatedFromMark(t *testing.T) {
	skip := fixedIntentSkipPayload()
	dSkip, err := computeIntentSkipDigest(skip)
	if err != nil {
		t.Fatalf("skip digest: %v", err)
	}

	mark := fixedIntentMarkPayload() // same agent/intent/nonce/expiry/domain; result "escrow#42"
	mark.Message.IntentID = skip.Message.IntentID
	mark.Message.Nonce = skip.Message.Nonce
	mark.Message.Result = skip.Message.Reason // even if the string slot matches, the typehash differs
	dMark, err := computeIntentMarkDigest(mark)
	if err != nil {
		t.Fatalf("mark digest: %v", err)
	}
	if hex.EncodeToString(dSkip) == hex.EncodeToString(dMark) {
		t.Fatal("skip and mark digests must differ (distinct commitment types)")
	}
}
