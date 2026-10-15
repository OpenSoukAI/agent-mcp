package main

import (
	"context"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/x402-foundation/x402/go/mechanisms/evm"
)

// Every typed-data builder must hash to exactly the digest the hand-rolled encoder produces: a
// policy backend (REF-492) signs the typed data, so a wrong field type or order would make it sign
// a different message than the one the backend verifies.

var tdDomain = commitmentDomain{ChainID: 84532, VerifyingContract: "0x5FC8d32690cc91D4c39d9d3abcBD16989F875707"}

func withName(d commitmentDomain, name string) commitmentDomain {
	d.Name, d.Version = name, "1"
	return d
}

func mustHash(t *testing.T, td apitypes.TypedData, err error) []byte {
	t.Helper()
	if err != nil {
		t.Fatalf("build typed data: %v", err)
	}
	h, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		t.Fatalf("hash typed data: %v", err)
	}
	return h
}

func assertSame(t *testing.T, name string, got, want []byte, wantErr error) {
	t.Helper()
	if wantErr != nil {
		t.Fatalf("%s: hand-rolled digest: %v", name, wantErr)
	}
	if string(got) != string(want) {
		t.Fatalf("%s: typed-data hash %x != hand-rolled digest %x", name, got, want)
	}
}

const (
	b32a = "0x" + "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"
	b32b = "0x" + "0011223344556677889900112233445566778899001122334455667788990011"
)

func TestTypedData_Review(t *testing.T) {
	p := reviewCommitmentPayload{Domain: withName(tdDomain, "ReviewRegistry"), Message: commitmentMessage{
		AgentID: "7", MerchantID: "4", ProductID: b32a, ContentHash: b32b, Nonce: "123456789", Expiry: "1893456000"}}
	td, err := reviewTypedData(p)
	want, werr := computeDigest(p)
	assertSame(t, "review", mustHash(t, td, err), want, werr)
}

func TestTypedData_Vote(t *testing.T) {
	p := voteCommitmentPayload{Domain: withName(tdDomain, "ReferrerVotes"), Message: voteCommitmentMessage{
		AgentID: "3", EscrowID: "42", VotesHash: b32a, Nonce: "99", Expiry: "1893456000"}}
	td, err := voteTypedData(p)
	want, werr := computeVoteDigest(p)
	assertSame(t, "vote", mustHash(t, td, err), want, werr)
}

func TestTypedData_CashbackRate(t *testing.T) {
	p := cashbackRateCommitmentPayload{Domain: withName(tdDomain, "ReferrerCashbackRate"), Message: cashbackRateCommitmentMessage{
		AgentID: "7", CashbackOfCommissionBps: "1500", Nonce: b32a, Expiry: "1893456000"}}
	td, err := cashbackRateTypedData(p)
	want, werr := computeCashbackRateDigest(p)
	assertSame(t, "cashback", mustHash(t, td, err), want, werr)
}

func TestTypedData_IntentAccess(t *testing.T) {
	p := fixedIntentAccessPayload()
	td, err := intentAccessTypedData(p)
	want, werr := computeIntentAccessDigest(p)
	assertSame(t, "intent access", mustHash(t, td, err), want, werr)
}

func TestTypedData_IntentMark(t *testing.T) {
	p := fixedIntentMarkPayload()
	td, err := intentMarkTypedData(p)
	want, werr := computeIntentMarkDigest(p)
	assertSame(t, "intent mark", mustHash(t, td, err), want, werr)
}

func TestTypedData_IntentSkip(t *testing.T) {
	p := fixedIntentSkipPayload()
	td, err := intentSkipTypedData(p)
	want, werr := computeIntentSkipDigest(p)
	assertSame(t, "intent skip", mustHash(t, td, err), want, werr)
}

func TestTypedData_TelegramLink(t *testing.T) {
	p := fixedTelegramPayload()
	td, err := telegramLinkTypedData(p)
	want, werr := computeTelegramLinkDigest(p)
	assertSame(t, "telegram", mustHash(t, td, err), want, werr)
}

func TestTypedData_Charge(t *testing.T) {
	payer := common.HexToAddress("0x976EA74026E726554dB657fA54763abd0C3a0aa9")
	ref := common.HexToHash(b32a)
	tokenHash := common.HexToHash(b32b)
	router := common.HexToAddress("0xa513E6E4b8f2a923D98304ec87F64353C4D5C853")
	td, err := chargeTypedData(payer, ref, big.NewInt(3), tokenHash, 84532, router)
	want, werr := computeChargeDigest(payer, ref, big.NewInt(3), tokenHash, 84532, router)
	assertSame(t, "charge", mustHash(t, td, err), want, werr)
}

func TestTypedData_ERC3009Receive(t *testing.T) {
	auth := evm.ExactEIP3009Authorization{
		From: "0x976EA74026E726554dB657fA54763abd0C3a0aa9", To: "0xa513E6E4b8f2a923D98304ec87F64353C4D5C853",
		Value: "1000000", ValidAfter: "0", ValidBefore: "1893456000", Nonce: b32a,
	}
	usdc := "0x254a83eEbF1913E56EA951bf12FE375Aa86175b9"
	td, err := erc3009ReceiveTypedData(auth, big.NewInt(84532), usdc, "USD Coin", "2")
	want, werr := hashERC3009Receive(auth, big.NewInt(84532), usdc, "USD Coin", "2")
	assertSame(t, "erc3009", mustHash(t, td, err), want, werr)
}

// signTyped refuses to sign typed data whose hash is not the independently computed digest, so a
// builder bug is a refusal at signing time rather than a signature over the wrong message.
func TestSignTyped_RefusesMismatchedDigest(t *testing.T) {
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	p := fixedIntentAccessPayload()
	td, err := intentAccessTypedData(p)
	if err != nil {
		t.Fatal(err)
	}
	other := crypto.Keccak256([]byte("a different commitment"))
	if _, err := signTyped(context.Background(), newLocalSigner(key), td, other); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("want a mismatch refusal, got %v", err)
	}
	want, _ := computeIntentAccessDigest(p)
	if _, err := signTyped(context.Background(), newLocalSigner(key), td, want); err != nil {
		t.Fatalf("matching digest must sign: %v", err)
	}
}
