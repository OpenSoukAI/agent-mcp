package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

const openSessionTestKeyHex = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

func openSessionTestPayload(payer string) openSessionCommitmentPayload {
	return openSessionCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerMPPSession",
			Version:           "1",
			ChainID:           42431,
			VerifyingContract: "0x00000000000000000000000000000000000A0b0C",
		},
		Message: openSessionCommitmentMessage{
			Payer:                payer,
			Salt:                 "0x" + strings.Repeat("ab", 32),
			BuyerAgentID:         "3",
			AttributionTokenHash: "0x" + strings.Repeat("cd", 32),
		},
	}
}

// Guards against drift from the backend's signing/open_session.go type string.
func TestOpenSessionTypeStringMatchesBackend(t *testing.T) {
	const want = "OpenSessionCommitment(address payer,bytes32 salt,uint256 buyerAgentId,bytes32 attributionTokenHash)"
	if openSessionCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", openSessionCommitmentTypeString, want)
	}
}

func TestComputeOpenSessionDigestRoundTrip(t *testing.T) {
	privKey, err := crypto.HexToECDSA(openSessionTestKeyHex)
	if err != nil {
		t.Fatalf("parse key: %v", err)
	}
	wantAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	digest, err := computeOpenSessionDigest(openSessionTestPayload(wantAddr.Hex()))
	if err != nil {
		t.Fatalf("computeOpenSessionDigest: %v", err)
	}
	// Cross-repo byte-match: this exact vector hashed by backend signing.OpenSessionDigest.
	// Any drift in domain/typehash/field-order/types breaks this (and on-chain verification).
	const wantDigest = "0xcaf7967f27c62108e32371ffa0a399028621a1407cc599961d848c329d6f2ad5"
	if got := "0x" + hex.EncodeToString(digest); got != wantDigest {
		t.Fatalf("digest drift vs backend:\n got  %s\n want %s", got, wantDigest)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	pub, err := crypto.SigToPub(digest, sig)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != wantAddr {
		t.Fatalf("recovered %s, want %s", got.Hex(), wantAddr.Hex())
	}
}

func TestHandleSignOpenSession_Output(t *testing.T) {
	privKey, _ := crypto.HexToECDSA(openSessionTestKeyHex)
	payerAddr := crypto.PubkeyToAddress(privKey.PublicKey)

	ks, err := parseKeystore("", "0x"+openSessionTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	signerKeys = ks

	_, out, err := handleSignOpenSession(nil, nil, signOpenSessionInput{Commitment: openSessionTestPayload(payerAddr.Hex())})
	if err != nil {
		t.Fatalf("handleSignOpenSession: %v", err)
	}
	if !strings.HasPrefix(out.Signature, "0x") {
		t.Fatalf("signature missing 0x prefix: %s", out.Signature)
	}
	sigBytes, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sigBytes) != 65 {
		t.Fatalf("signature length %d (want 65)", len(sigBytes))
	}
	if sigBytes[64] != 27 && sigBytes[64] != 28 {
		t.Fatalf("v=%d (want 27/28)", sigBytes[64])
	}
	// Strip the +27 offset and confirm it recovers to the payer (= what the backend checks).
	norm := make([]byte, 65)
	copy(norm, sigBytes)
	norm[64] -= 27
	digest, _ := computeOpenSessionDigest(openSessionTestPayload(payerAddr.Hex()))
	pub, err := crypto.SigToPub(digest, norm)
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != payerAddr {
		t.Fatalf("recovered %s, want payer %s", got.Hex(), payerAddr.Hex())
	}
}

func TestHandleSignOpenSession_PayerMismatch(t *testing.T) {
	ks, err := parseKeystore("", "0x"+openSessionTestKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	signerKeys = ks
	// Payer is some other address than the key's → sanity check must reject.
	p := openSessionTestPayload("0x9999999999999999999999999999999999999999")
	if _, _, err := handleSignOpenSession(nil, nil, signOpenSessionInput{Commitment: p}); err == nil {
		t.Fatal("expected error: signing key does not match payer")
	}
}
