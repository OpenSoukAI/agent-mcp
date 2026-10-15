package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// fixedTelegramPayload builds a representative step-1 commitment payload.
func fixedTelegramPayload() telegramLinkCommitmentPayload {
	return telegramLinkCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerTelegramLink",
			Version:           "1",
			ChainID:           84532, // Base Sepolia
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: telegramLinkCommitmentMessage{
			AgentID: "7",
			Nonce:   "0x" + strings.Repeat("ab", 32), // 32 bytes
			Expiry:  "1893456000",
		},
	}
}

// TestTelegramLinkTypeString_MatchesBackend pins the EIP-712 type string byte-for-byte
// to the backend (internal/signing/telegram_link_commitment.go). A drift here would make
// every signature this tool produces fail backend verification.
func TestTelegramLinkTypeString_MatchesBackend(t *testing.T) {
	const want = "TelegramLinkCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"
	if telegramLinkCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", telegramLinkCommitmentTypeString, want)
	}
}

// TestSignTelegramLink_RoundTrip signs a commitment and recovers the signer from the
// digest, proving the produced 65-byte sig is valid over computeTelegramLinkDigest and
// that the v-byte is normalized to 27/28.
func TestSignTelegramLink_RoundTrip(t *testing.T) {
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "0x000000000000000000000000000000000000aBcD")
	resetAddressCache()
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)

	// Load the key for agent "7" via the real keystore path.
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	p := fixedTelegramPayload()
	_, out, err := handleSignTelegramLink(nil, nil, signTelegramLinkInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignTelegramLink: %v", err)
	}

	digest, err := computeTelegramLinkDigest(p)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}

	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	if len(sig) != 65 {
		t.Fatalf("signature length = %d, want 65", len(sig))
	}

	// Recover: crypto.SigToPub expects v=0/1, tool emits v=27/28.
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
