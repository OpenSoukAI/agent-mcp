package main

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
)

// recordingSigner records which Signer method each tool used. A policy backend (REF-492) can only
// enforce a policy on SignTypedData; a tool that calls SignDigest for an EIP-712 message would
// hand it an opaque hash.
type recordingSigner struct {
	inner      Signer
	primaries  []string
	rawDigests int
}

func (r *recordingSigner) Address() common.Address { return r.inner.Address() }

func (r *recordingSigner) SignDigest(ctx context.Context, d [32]byte) ([]byte, error) {
	r.rawDigests++
	return r.inner.SignDigest(ctx, d)
}

func (r *recordingSigner) SignTypedData(ctx context.Context, td apitypes.TypedData) ([]byte, error) {
	r.primaries = append(r.primaries, td.PrimaryType)
	return r.inner.SignDigest(ctx, mustTDHash(td))
}

func mustTDHash(td apitypes.TypedData) [32]byte {
	h, _, err := apitypes.TypedDataAndHash(td)
	if err != nil {
		panic(err)
	}
	var out [32]byte
	copy(out[:], h)
	return out
}

func recordingKeystore(t *testing.T) *recordingSigner {
	t.Helper()
	key, _ := crypto.HexToECDSA(testLocalKeyHex)
	rec := &recordingSigner{inner: newLocalSigner(key)}
	prev := signerKeys
	signerKeys = &keystore{keys: map[string]Signer{}, fallback: rec}
	t.Cleanup(func() { signerKeys = prev })
	return rec
}

func assertTypedOnly(t *testing.T, rec *recordingSigner, primary string) {
	t.Helper()
	if len(rec.primaries) != 1 || rec.primaries[0] != primary {
		t.Fatalf("SignTypedData calls %v, want exactly [%s]", rec.primaries, primary)
	}
	if rec.rawDigests != 0 {
		t.Fatalf("SignDigest called %d times; the tool must not sign a raw digest itself", rec.rawDigests)
	}
}

type commitmentToolCase struct {
	primary string
	call    func() error
}

// commitmentToolCases calls each EIP-712 commitment tool with a payload pinEnv accepts.
func commitmentToolCases() []commitmentToolCase {
	return []commitmentToolCase{
		{"ReviewCommitment", func() error {
			_, _, err := handleSign(context.Background(), nil, signInput{Commitment: reviewCommitmentPayload{
				Domain:  goodReviewDomain(),
				Message: commitmentMessage{AgentID: "7", MerchantID: "4", ProductID: b32a, ContentHash: b32b, Nonce: "1", Expiry: "1893456000"}}})
			return err
		}},
		{"VoteCommitment", func() error {
			_, _, err := handleSignVote(context.Background(), nil, signVoteInput{Commitment: voteCommitmentPayload{
				Domain:  withName(commitmentDomain{ChainID: 84532, VerifyingContract: pinTestRegistry}, "ReferrerVotes"),
				Message: voteCommitmentMessage{AgentID: "7", EscrowID: "42", VotesHash: b32a, Nonce: "7", Expiry: "1893456000"}}})
			return err
		}},
		{"CashbackRateCommitment", func() error {
			_, _, err := handleSignCashbackRate(context.Background(), nil, signCashbackRateInput{Commitment: cashbackRateCommitmentPayload{
				Domain:  withName(commitmentDomain{ChainID: 84532, VerifyingContract: pinTestRegistry}, "ReferrerCashbackRate"),
				Message: cashbackRateCommitmentMessage{AgentID: "7", CashbackOfCommissionBps: "1000", Nonce: b32a, Expiry: "1893456000"}}})
			return err
		}},
		{"IntentAccessCommitment", func() error {
			p := fixedIntentAccessPayload()
			p.Domain.VerifyingContract = pinTestRegistry
			_, _, err := handleSignIntentAccess(context.Background(), nil, signIntentAccessInput{Commitment: p})
			return err
		}},
		{"IntentMarkCommitment", func() error {
			p := fixedIntentMarkPayload()
			p.Domain.VerifyingContract = pinTestRegistry
			_, _, err := handleSignIntentMark(context.Background(), nil, signIntentMarkInput{Commitment: p})
			return err
		}},
		{"IntentSkipCommitment", func() error {
			p := fixedIntentSkipPayload()
			p.Domain.VerifyingContract = pinTestRegistry
			_, _, err := handleSignIntentSkip(context.Background(), nil, signIntentSkipInput{Commitment: p})
			return err
		}},
		{"TelegramLinkCommitment", func() error {
			p := fixedTelegramPayload()
			p.Domain.VerifyingContract = pinTestRegistry
			_, _, err := handleSignTelegramLink(context.Background(), nil, signTelegramLinkInput{Commitment: p})
			return err
		}},
		{"ChargeCommitment", func() error {
			in := validChargeInput()
			in.SplitRouterAddr = pinTestRouter
			_, _, err := handleSignCharge(context.Background(), nil, in)
			return err
		}},
	}
}

func TestEveryCommitmentToolSignsTypedData(t *testing.T) {
	for _, c := range commitmentToolCases() {
		t.Run(c.primary, func(t *testing.T) {
			pinEnv(t)
			rec := recordingKeystore(t)
			if err := c.call(); err != nil {
				t.Fatalf("tool refused a valid commitment: %v", err)
			}
			assertTypedOnly(t, rec, c.primary)
		})
	}
}

func TestPayForProductSignsERC3009AsTypedData(t *testing.T) {
	if stubTxErr != nil {
		t.Fatalf("build stub tx: %v", stubTxErr)
	}
	refLink := payTestEnv(t, http.StatusOK, `{"transaction":"`+stubTx.Hash().Hex()+`"}`)
	rec := &recordingSigner{inner: signerKeys.fallback}
	signerKeys = &keystore{keys: map[string]Signer{}, fallback: rec}

	if _, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{RefLink: refLink, AgentID: "12"}); err != nil &&
		!strings.Contains(err.Error(), "escrow") {
		t.Fatalf("pay_for_product: %v", err)
	}
	if len(rec.primaries) == 0 || rec.primaries[0] != erc3009ReceiveAuthorizationType {
		t.Fatalf("SignTypedData calls %v, want %s first", rec.primaries, erc3009ReceiveAuthorizationType)
	}
}

func TestCastVotesSignsTypedData(t *testing.T) {
	startFakeVoteBackend(t, 0)
	rec := &recordingSigner{inner: newLocalSigner(testKey(t))}
	if _, err := castVotesViaBackend(context.Background(), "inmemory://test", 5, 55, []voteArg{{43, "influenced my choice"}}, rec); err != nil {
		t.Fatalf("castVotesViaBackend: %v", err)
	}
	assertTypedOnly(t, rec, "VoteCommitment")
}
