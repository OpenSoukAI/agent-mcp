package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// policyRecorder stands in for a policy backend: it signs whole transactions and personal
// messages itself, and fails the test if anything reaches SignDigest.
type policyRecorder struct {
	*localSigner
	t        *testing.T
	key      *ecdsa.PrivateKey
	txs      int
	messages [][]byte
}

func newPolicyRecorder(t *testing.T) *policyRecorder {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	return &policyRecorder{localSigner: newLocalSigner(key), t: t, key: key}
}

func (r *policyRecorder) SignDigest(context.Context, [32]byte) ([]byte, error) {
	r.t.Error("SignDigest reached a backend that signs transactions and messages itself")
	return nil, errRawDigestRefused
}

func (r *policyRecorder) SignTx(_ context.Context, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
	r.txs++
	return types.SignTx(tx, types.LatestSignerForChainID(chainID), r.key)
}

func (r *policyRecorder) SignPersonalMessage(_ context.Context, msg []byte) ([]byte, error) {
	r.messages = append(r.messages, append([]byte(nil), msg...))
	return crypto.Sign(accounts.TextHash(msg), r.key)
}

func TestTransactOptsPrefersTxSigner(t *testing.T) {
	rec := newPolicyRecorder(t)
	chainID := big.NewInt(84532)
	opts := transactOpts(context.Background(), rec, chainID)
	to := common.HexToAddress("0x0000000000000000000000000000000000000002")
	tx := types.NewTx(&types.DynamicFeeTx{ChainID: chainID, Nonce: 1, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(2), Gas: 21000, To: &to})
	signed, err := opts.Signer(opts.From, tx)
	if err != nil {
		t.Fatal(err)
	}
	if rec.txs != 1 {
		t.Fatalf("SignTx called %d times, want 1", rec.txs)
	}
	if from, _ := types.Sender(types.LatestSignerForChainID(chainID), signed); from != rec.Address() {
		t.Fatalf("sender %s", from.Hex())
	}
}

func TestAgentAuthPrefersMessageSigner(t *testing.T) {
	rec := newPolicyRecorder(t)
	body, ts := []byte(`{"x":1}`), int64(1792000000)
	sigHex, err := agentAuthSignature(context.Background(), body, ts, rec)
	if err != nil {
		t.Fatal(err)
	}
	want := agentAuthPayloadHash(body, ts)
	if len(rec.messages) != 1 || hex.EncodeToString(rec.messages[0]) != hex.EncodeToString(want) {
		t.Fatalf("personal message %x, want the raw 32-byte payload hash %x", rec.messages, want)
	}
	if !strings.HasSuffix(sigHex, "1b") && !strings.HasSuffix(sigHex, "1c") {
		t.Fatalf("signature %s must carry v=27/28", sigHex)
	}
	if got, err := recoverAgentAuth(body, ts, sigHex); err != nil || !strings.EqualFold(got, rec.Address().Hex()) {
		t.Fatalf("recovers to %s (%v), want %s", got, err, rec.Address().Hex())
	}
}

func TestCheckSig65(t *testing.T) {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	other, _ := crypto.GenerateKey()
	want := crypto.PubkeyToAddress(key.PublicKey)
	for _, d := range digestsForBothV(t, key) {
		sig, _ := crypto.Sign(d[:], key)
		for _, variant := range []struct {
			name string
			mut  func([]byte) []byte
		}{
			{"v0/1", func(s []byte) []byte { return s }},
			{"v27/28", func(s []byte) []byte { s[64] += 27; return s }},
			{"high-s", func(s []byte) []byte {
				hs := new(big.Int).Sub(secp256k1N, new(big.Int).SetBytes(s[32:64]))
				hs.FillBytes(s[32:64])
				s[64] ^= 1
				return s
			}},
		} {
			got, err := checkSig65(variant.mut(append([]byte(nil), sig...)), d, want)
			if err != nil {
				t.Fatalf("%s: %v", variant.name, err)
			}
			if got[64] > 1 || new(big.Int).SetBytes(got[32:64]).Cmp(secp256k1HalfN) > 0 {
				t.Fatalf("%s: not normalised (v=%d)", variant.name, got[64])
			}
			if pub, err := crypto.SigToPub(d[:], got); err != nil || crypto.PubkeyToAddress(*pub) != want {
				t.Fatalf("%s: does not recover", variant.name)
			}
		}
		bad, _ := crypto.Sign(d[:], other)
		if _, err := checkSig65(bad, d, want); err == nil || !strings.Contains(err.Error(), want.Hex()) {
			t.Fatalf("another key's signature must be refused naming %s, got %v", want.Hex(), err)
		}
	}
	if _, err := checkSig65(make([]byte, 64), [32]byte{}, want); err == nil {
		t.Fatal("a 64-byte signature must be refused")
	}
}
