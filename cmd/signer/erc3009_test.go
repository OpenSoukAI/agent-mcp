package main

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
)

// Cross-language ERC-3009 digest vector (REF-269 item 8).
//
// Same fixed authorization, same pinned digest as:
//
//   - contracts/test/unit/ERC3009VectorTest.t.sol
//   - backend/internal/signing/erc3009_vector_test.go
//   - frontend/app/buy/erc3009Vector.test.ts
//
// This signer and the backend validator must agree exactly: the signer produces the signature the
// validator recovers. They reach the digest through separate code, so a shared vector is the only
// thing that catches a divergence before an agent's purchase silently fails.
//
// Regenerating the expected value is not a fix. If a change makes these disagree, one side is
// wrong — find which with contracts/test/fork/SplitRouterUSDCFork.t.sol, which asserts against
// real Circle USDC rather than against us.
const (
	vectorFrom        = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
	vectorTo          = "0x2222222222222222222222222222222222222222"
	vectorNonce       = "0x00000000000000000000000000000000000000000000000000000000000000ff"
	vectorChainID     = 8453
	vectorToken       = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
	vectorName        = "USD Coin"
	vectorVersion     = "2"
	vectorSignerKey   = "4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318"
	wantReceiveDigest = "0x6c522c286cd69c50477f7362c599451191365984c518ebba8eb0bdadc3a3f96a"
)

func vectorAuth() evm.ExactEIP3009Authorization {
	return evm.ExactEIP3009Authorization{
		From:        vectorFrom,
		To:          vectorTo,
		Value:       "1000000", // 1 USDC, 6 decimals
		ValidAfter:  "0",
		ValidBefore: "1893456000", // 2030-01-01T00:00:00Z
		Nonce:       vectorNonce,
	}
}

func TestHashERC3009Receive_MatchesCrossLanguageVector(t *testing.T) {
	got, err := hashERC3009Receive(vectorAuth(), big.NewInt(vectorChainID), vectorToken, vectorName, vectorVersion)
	if err != nil {
		t.Fatalf("hashERC3009Receive: %v", err)
	}
	if h := "0x" + hex.EncodeToString(got); h != wantReceiveDigest {
		t.Fatalf("digest = %s, want %s — this signer now disagrees with the backend validator, so "+
			"every purchase it signs will be rejected", h, wantReceiveDigest)
	}
}

// TestHashERC3009Receive_DiffersFromTransfer pins the reason this file exists. If the two ever
// hash alike, the pre-REF-269 signature would settle and this whole change would be moot.
func TestHashERC3009Receive_DiffersFromTransfer(t *testing.T) {
	transfer, err := evm.HashEIP3009Authorization(
		vectorAuth(), big.NewInt(vectorChainID), vectorToken, vectorName, vectorVersion,
	)
	if err != nil {
		t.Fatalf("HashEIP3009Authorization: %v", err)
	}
	if h := "0x" + hex.EncodeToString(transfer); h == wantReceiveDigest {
		t.Fatalf("Transfer and Receive digests are equal (%s); the typehashes are not distinct", h)
	}
}

// TestHashERC3009Receive_SignatureRecoversTheSigner is the property pay_for_product depends on:
// the backend must recover the buyer address from what this signer produced.
func TestHashERC3009Receive_SignatureRecoversTheSigner(t *testing.T) {
	key, err := crypto.HexToECDSA(vectorSignerKey)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	signer := crypto.PubkeyToAddress(key.PublicKey)
	if signer != common.HexToAddress(vectorFrom) {
		t.Fatalf("vectorFrom = %s, but vectorSignerKey yields %s", vectorFrom, signer.Hex())
	}

	hash, err := hashERC3009Receive(vectorAuth(), big.NewInt(vectorChainID), vectorToken, vectorName, vectorVersion)
	if err != nil {
		t.Fatalf("hashERC3009Receive: %v", err)
	}
	sig, err := crypto.Sign(hash, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, err := crypto.SigToPub(hash, sig)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != signer {
		t.Fatalf("recovered %s, want %s", got.Hex(), signer.Hex())
	}
}
