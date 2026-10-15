package main

import (
	"context"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// TestKMSLive drives a real KMS endpoint through the AWS SDK: AWS itself, or an emulator via
// AWS_ENDPOINT_URL. Gated: REF490_KMS_LIVE=1 and REF490_KMS_KEY_ID. With BASE_RPC_URL set it also
// sends a 1-wei KMS-signed transaction (the key's address must hold gas). Stock moto fails the
// digest check: it ignores MessageType=DIGEST and re-hashes the message with SHA-256.
func TestKMSLive(t *testing.T) {
	keyID := os.Getenv("REF490_KMS_KEY_ID")
	if os.Getenv("REF490_KMS_LIVE") != "1" || keyID == "" {
		t.Skip("set REF490_KMS_LIVE=1 and REF490_KMS_KEY_ID to run")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	api, err := defaultKMSClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newKMSSigner(ctx, api, keyID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("KMS key %s signs as %s", keyID, s.Address().Hex())

	for i := 0; i < 8; i++ { // several digests, so both recovery ids and both s halves occur
		digest := crypto.Keccak256Hash([]byte{byte(i)}, []byte("ref-490 live"))
		sig, err := s.SignDigest(ctx, digest)
		if err != nil {
			t.Fatalf("digest %d: %v", i, err)
		}
		pub, err := crypto.SigToPub(digest[:], sig)
		if err != nil || crypto.PubkeyToAddress(*pub) != s.Address() {
			t.Fatalf("digest %d: does not recover to the KMS key", i)
		}
	}

	td, err := intentAccessTypedData(fixedIntentAccessPayload())
	if err != nil {
		t.Fatal(err)
	}
	sig, err := s.SignTypedData(ctx, td)
	if err != nil {
		t.Fatal(err)
	}
	hash, _, _ := apitypes.TypedDataAndHash(td)
	if pub, err := crypto.SigToPub(hash, sig); err != nil || crypto.PubkeyToAddress(*pub) != s.Address() {
		t.Fatal("typed-data signature does not recover to the KMS key")
	}

	rpc := os.Getenv("BASE_RPC_URL")
	if rpc == "" {
		return
	}
	client, err := ethclient.DialContext(ctx, rpc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	chainID, err := client.ChainID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := client.PendingNonceAt(ctx, s.Address())
	if err != nil {
		t.Fatal(err)
	}
	tip, err := client.SuggestGasTipCap(ctx)
	if err != nil {
		t.Fatal(err)
	}
	head, err := client.HeaderByNumber(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	feeCap := new(big.Int).Add(new(big.Int).Mul(head.BaseFee, big.NewInt(2)), tip)
	to := common.HexToAddress("0x000000000000000000000000000000000000dEaD")
	opts := transactOpts(ctx, s, chainID)
	tx, err := opts.Signer(opts.From, types.NewTx(&types.DynamicFeeTx{
		ChainID: chainID, Nonce: nonce, GasTipCap: tip, GasFeeCap: feeCap, Gas: 21000, To: &to, Value: big.NewInt(1),
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.SendTransaction(ctx, tx); err != nil {
		t.Fatalf("send KMS-signed tx: %v", err)
	}
	for {
		r, err := client.TransactionReceipt(ctx, tx.Hash())
		if err == nil {
			if r.Status != types.ReceiptStatusSuccessful {
				t.Fatalf("tx %s reverted", tx.Hash().Hex())
			}
			t.Logf("KMS-signed tx %s mined in block %d", tx.Hash().Hex(), r.BlockNumber)
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("no receipt for %s: %v", tx.Hash().Hex(), ctx.Err())
		case <-time.After(500 * time.Millisecond):
		}
	}
}
