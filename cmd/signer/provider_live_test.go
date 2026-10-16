package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
)

// TestProviderLive runs the generated policy against a real Turnkey or Privy account. Gated:
// REF492_LIVE=turnkey|privy, the provider's credentials as the signer reads them, REF492_WALLET
// (the AGENT_WALLETS ref), CHAIN_ID + the contract addresses (BASE_RPC_URL, or the *_ADDRESS
// overrides), USDC_ADDRESS and MAX_PAYMENT_PER_TX, i.e. what the policy was generated with.
//
// Everything allowed must sign; everything else must be refused BY THE PROVIDER: the adapter
// itself does not check domains, so a refusal here is the policy's.
func TestProviderLive(t *testing.T) {
	provider := os.Getenv("REF492_LIVE")
	if provider != "turnkey" && provider != "privy" {
		t.Skip("set REF492_LIVE=turnkey|privy and the provider credentials to run")
	}
	t.Setenv("SIGNER_BACKEND", provider)
	t.Setenv("AGENT_WALLETS", "*:"+os.Getenv("REF492_WALLET"))
	resetAddressCache()
	ctx := context.Background()
	ks, report, err := loadKeystore(ctx, os.Getenv, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(report)
	s := ks.fallback
	chainID, err := configuredChainID()
	if err != nil {
		t.Fatal(err)
	}
	addr := map[protocolKey]common.Address{}
	for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter} {
		if addr[k], err = resolveAddress(ctx, chainID, k); err != nil {
			t.Fatal(err)
		}
	}
	usdc := os.Getenv("USDC_ADDRESS")
	ceiling, ok := new(big.Int).SetString(os.Getenv("MAX_PAYMENT_PER_TX"), 10)
	if !common.IsHexAddress(usdc) || !ok {
		t.Fatal("set USDC_ADDRESS and MAX_PAYMENT_PER_TX to the values the policy was generated with")
	}
	usdcName, usdcVersion := envOr("REF492_USDC_NAME", "USDC"), envOr("REF492_USDC_VERSION", "2")

	receive := func(primary string, value *big.Int) apitypes.TypedData {
		var nonce [32]byte
		_, _ = rand.Read(nonce[:])
		td, err := erc3009ReceiveTypedData(evm.ExactEIP3009Authorization{From: s.Address().Hex(), To: addr[keySplitRouter].Hex(), Value: value.String(),
			ValidAfter: "0", ValidBefore: strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10), Nonce: "0x" + hex.EncodeToString(nonce[:])},
			big.NewInt(chainID), usdc, usdcName, usdcVersion)
		if err != nil {
			t.Fatal(err)
		}
		if primary != td.PrimaryType {
			td.Types[primary] = td.Types[td.PrimaryType]
			delete(td.Types, td.PrimaryType)
			td.PrimaryType = primary
		}
		return td
	}
	tx := func(to common.Address, selector string, value int64) *types.Transaction {
		data, _ := hexutil.Decode(selector)
		data = append(data, make([]byte, 64)...)
		return types.NewTx(&types.DynamicFeeTx{ChainID: big.NewInt(chainID), Nonce: 0, GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1_000_000_000),
			Gas: 200000, To: &to, Value: big.NewInt(value), Data: data})
	}
	signTx := func(t *testing.T, x *types.Transaction) error {
		_, err := transactOpts(ctx, s, big.NewInt(chainID)).Signer(s.Address(), x)
		return err
	}

	t.Run("allowed", func(t *testing.T) {
		for _, spec := range allSpecs {
			if _, err := s.SignTypedData(ctx, specTypedData(spec, chainID, addr[spec.contract].Hex())); err != nil {
				t.Errorf("%s: %v", spec.primary, err)
			}
		}
		if _, err := s.SignTypedData(ctx, receive(erc3009ReceiveAuthorizationType, ceiling)); err != nil {
			t.Errorf("ReceiveWithAuthorization at the ceiling: %v", err)
		}
		if err := signTx(t, tx(addr[keyReviewRegistry], hexSelector(keyReviewRegistry, "updateReviewContent"), 0)); err != nil {
			t.Errorf("updateReviewContent tx: %v", err)
		}
		if provider == "privy" {
			if _, err := agentAuthSignature(ctx, []byte(`{"live":true}`), time.Now().Unix(), s); err != nil {
				t.Errorf("agent auth personal_sign: %v", err)
			}
		}
	})

	refused := func(t *testing.T, name string, err error) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: SIGNED; the policy must refuse it", name)
			return
		}
		marker := "HTTP 4"
		if provider == "turnkey" && strings.Contains(err.Error(), "Turnkey refused") {
			marker = "Turnkey refused"
		}
		if !strings.Contains(err.Error(), marker) {
			t.Errorf("%s: refused, but not by the provider: %v", name, err)
			return
		}
		t.Logf("%s: refused by %s: %v", name, provider, err)
	}
	t.Run("refused by the provider", func(t *testing.T) {
		review := specTypedData(specReview, chainID, addr[keyReviewRegistry].Hex())
		foreign := review
		foreign.Types = apitypes.Types{"EIP712Domain": review.Types["EIP712Domain"], "EvilCommitment": review.Types["ReviewCommitment"]}
		foreign.PrimaryType = "EvilCommitment"
		_, err := s.SignTypedData(ctx, foreign)
		refused(t, "foreign primary type", err)
		_, err = s.SignTypedData(ctx, specTypedData(specReview, chainID+1, addr[keyReviewRegistry].Hex()))
		refused(t, "wrong chainId", err)
		_, err = s.SignTypedData(ctx, specTypedData(specReview, chainID, "0x000000000000000000000000000000000000dEaD"))
		refused(t, "wrong verifyingContract", err)
		_, err = s.SignTypedData(ctx, receive("TransferWithAuthorization", big.NewInt(1)))
		refused(t, "TransferWithAuthorization", err)
		over := new(big.Int).Add(ceiling, big.NewInt(1))
		_, err = s.SignTypedData(ctx, receive(erc3009ReceiveAuthorizationType, over))
		refused(t, "ReceiveWithAuthorization one over the ceiling", err)
		// Numerically larger but lexicographically smaller than the ceiling: catches a policy
		// engine that compares the decimal strings as text.
		if ceiling.String()[0] > '1' {
			lex := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(len(ceiling.String()))), nil)
			_, err = s.SignTypedData(ctx, receive(erc3009ReceiveAuthorizationType, lex))
			refused(t, "ReceiveWithAuthorization "+lex.String()+" (text-compares below the ceiling)", err)
		} else {
			t.Log("ceiling starts with 1: the text-comparison case needs a ceiling starting 2-9")
		}
		refused(t, "tx with an unlisted selector", signTx(t, tx(addr[keyReviewRegistry], "0xdeadbeef", 0)))
		refused(t, "tx with ETH value", signTx(t, tx(addr[keyReviewRegistry], hexSelector(keyReviewRegistry, "updateReviewContent"), 1)))
		refused(t, "tx to the SplitRouter", signTx(t, tx(addr[keySplitRouter], hexSelector(keyReviewRegistry, "updateReviewContent"), 0)))

		var digest [32]byte
		_, _ = rand.Read(digest[:])
		switch ps := s.(type) {
		case *turnkeySigner:
			_, err = ps.c.activity(ctx, "/public/v1/submit/sign_raw_payload", "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", map[string]any{
				"signWith": strings.ToLower(ps.addr.Hex()), "payload": hex.EncodeToString(digest[:]), "encoding": "PAYLOAD_ENCODING_HEXADECIMAL", "hashFunction": "HASH_FUNCTION_NO_OP"})
			refused(t, "raw digest (HEXADECIMAL, NO_OP)", err)
			_, err = ps.c.activity(ctx, "/public/v1/submit/sign_raw_payload", "ACTIVITY_TYPE_SIGN_RAW_PAYLOAD_V2", map[string]any{
				"signWith": strings.ToLower(ps.addr.Hex()), "payload": hex.EncodeToString(digest[:]), "encoding": "PAYLOAD_ENCODING_HEXADECIMAL", "hashFunction": "HASH_FUNCTION_KECCAK256"})
			refused(t, "raw bytes (HEXADECIMAL, KECCAK256)", err)
		case *privySigner:
			_, err = ps.rpc(ctx, "secp256k1_sign", map[string]any{"hash": hexutil.Encode(digest[:])}, "signature")
			refused(t, "raw digest (secp256k1_sign)", err)
			_, err = ps.SignPersonalMessage(ctx, make([]byte, 64))
			refused(t, "personal_sign of 64 bytes", err)
		}
	})
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}
