package main

import (
	"context"
	"strings"
	"testing"
)

const (
	pinTestRegistry = "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF"
	pinTestRouter   = "0x5555555555555555555555555555555555555555"
)

// pinEnv configures the signer for chain 84532 with env-overridden contract addresses, so no
// RPC happens on the pin path.
func pinEnv(t *testing.T) {
	t.Helper()
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("REVIEW_REGISTRY_ADDRESS", pinTestRegistry)
	t.Setenv("SPLIT_ROUTER_ADDRESS", pinTestRouter)
	resetAddressCache()
	// An empty keystore, so a handler that reaches the key lookup fails by assertion
	// ("no key for agent") rather than by a nil-receiver panic.
	prev := signerKeys
	signerKeys = &keystore{keys: map[string]Signer{}}
	t.Cleanup(func() { signerKeys = prev })
}

func goodReviewDomain() commitmentDomain {
	return commitmentDomain{Name: "ReviewRegistry", Version: "1", ChainID: 84532, VerifyingContract: pinTestRegistry}
}

func TestPinDomain_Accepts(t *testing.T) {
	pinEnv(t)
	if err := pinDomain(context.Background(), goodReviewDomain(), specReview); err != nil {
		t.Fatal(err)
	}
}

func TestPinDomain_ChecksumInsensitive(t *testing.T) {
	pinEnv(t)
	d := goodReviewDomain()
	d.VerifyingContract = strings.ToLower(pinTestRegistry)
	if err := pinDomain(context.Background(), d, specReview); err != nil {
		t.Fatalf("lower-case address must pass: %v", err)
	}
}

func TestPinDomain_RefusesWrongChain(t *testing.T) {
	pinEnv(t)
	d := goodReviewDomain()
	d.ChainID = 1
	err := pinDomain(context.Background(), d, specReview)
	if err == nil || !strings.Contains(err.Error(), "chainId 1") || !strings.Contains(err.Error(), "84532") {
		t.Fatalf("want chain mismatch naming both ids, got %v", err)
	}
}

func TestPinDomain_RefusesWrongContract(t *testing.T) {
	pinEnv(t)
	d := goodReviewDomain()
	d.VerifyingContract = "0x9999999999999999999999999999999999999999"
	err := pinDomain(context.Background(), d, specReview)
	if err == nil || !strings.Contains(err.Error(), "verifyingContract") || !strings.Contains(err.Error(), "REVIEW_REGISTRY") {
		t.Fatalf("want contract mismatch naming the key, got %v", err)
	}
}

func TestPinDomain_RefusesWrongName(t *testing.T) {
	pinEnv(t)
	d := goodReviewDomain()
	d.Name = "ReferrerVotes"
	err := pinDomain(context.Background(), d, specReview)
	if err == nil || !strings.Contains(err.Error(), `"ReferrerVotes"`) || !strings.Contains(err.Error(), `"ReviewRegistry"`) {
		t.Fatalf("want name mismatch naming both, got %v", err)
	}
}

func TestPinDomain_RefusesWrongVersion(t *testing.T) {
	pinEnv(t)
	d := goodReviewDomain()
	d.Version = "2"
	if err := pinDomain(context.Background(), d, specReview); err == nil {
		t.Fatal("want version mismatch")
	}
}

func TestPinDomain_ChargeUsesSplitRouter(t *testing.T) {
	pinEnv(t)
	d := commitmentDomain{Name: "ReferrerMPPCharge", Version: "1", ChainID: 84532, VerifyingContract: pinTestRouter}
	if err := pinDomain(context.Background(), d, specCharge); err != nil {
		t.Fatal(err)
	}
	d.VerifyingContract = pinTestRegistry // the review registry is NOT the charge domain
	if err := pinDomain(context.Background(), d, specCharge); err == nil {
		t.Fatal("charge domain must pin to SPLIT_ROUTER")
	}
}

func TestPinDomain_SpecTableMatchesBackend(t *testing.T) {
	want := map[string][3]string{
		"ReviewCommitment":       {"ReviewRegistry", "1", "REVIEW_REGISTRY"},
		"VoteCommitment":         {"ReferrerVotes", "1", "REVIEW_REGISTRY"},
		"CashbackRateCommitment": {"ReferrerCashbackRate", "1", "REVIEW_REGISTRY"},
		"IntentAccessCommitment": {"ReferrerIntentAccess", "1", "REVIEW_REGISTRY"},
		"IntentMarkCommitment":   {"ReferrerIntentAccess", "1", "REVIEW_REGISTRY"},
		"IntentSkipCommitment":   {"ReferrerIntentAccess", "1", "REVIEW_REGISTRY"},
		"TelegramLinkCommitment": {"ReferrerTelegramLink", "1", "REVIEW_REGISTRY"},
		"ChargeCommitment":       {"ReferrerMPPCharge", "1", "SPLIT_ROUTER"},
	}
	specs := []domainSpec{specReview, specVote, specCashbackRate, specIntentAccess, specIntentMark, specIntentSkip, specTelegramLink, specCharge}
	if len(specs) != len(want) {
		t.Fatalf("%d specs, want %d", len(specs), len(want))
	}
	for _, s := range specs {
		w, ok := want[s.primary]
		if !ok {
			t.Fatalf("unexpected primary %q", s.primary)
		}
		if s.name != w[0] || s.version != w[1] || string(s.contract) != w[2] {
			t.Errorf("%s: got %q/%q/%s", s.primary, s.name, s.version, s.contract)
		}
	}
}

// ── handler wiring: every sign tool refuses a foreign chain before producing a signature ──
//
// No keystore is configured in these tests: the pin must run before the key lookup, so a
// refusal here proves the pin is wired, not that a key was missing.

func foreignDomain(name string, contract string) commitmentDomain {
	return commitmentDomain{Name: name, Version: "1", ChainID: 1, VerifyingContract: contract}
}

func assertDomainRefusal(t *testing.T, out signOutput, err error) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), "chainId 1") {
		t.Fatalf("want domain refusal naming chainId 1, got err=%v", err)
	}
	if out.Signature != "" {
		t.Fatalf("no signature may be produced on refusal, got %q", out.Signature)
	}
}

func TestSignReview_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := reviewCommitmentPayload{
		Domain:  foreignDomain("ReviewRegistry", pinTestRegistry),
		Message: commitmentMessage{AgentID: "7", MerchantID: "1", ProductID: "0x" + strings.Repeat("00", 32), ContentHash: "0x" + strings.Repeat("ab", 32), Nonce: "1", Expiry: "9999999999"},
	}
	_, out, err := handleSign(nil, nil, signInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignVote_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := voteCommitmentPayload{
		Domain:  foreignDomain("ReferrerVotes", pinTestRegistry),
		Message: voteCommitmentMessage{AgentID: "1", EscrowID: "42", VotesHash: "0x" + strings.Repeat("ab", 32), Nonce: "7", Expiry: "9999999999"},
	}
	_, out, err := handleSignVote(nil, nil, signVoteInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignCashbackRate_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := cashbackRateCommitmentPayload{
		Domain:  foreignDomain("ReferrerCashbackRate", pinTestRegistry),
		Message: cashbackRateCommitmentMessage{AgentID: "7", CashbackOfCommissionBps: "1000", Nonce: "0x" + strings.Repeat("ab", 32), Expiry: "9999999999"},
	}
	_, out, err := handleSignCashbackRate(nil, nil, signCashbackRateInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignIntentAccess_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := fixedIntentAccessPayload()
	p.Domain = foreignDomain("ReferrerIntentAccess", pinTestRegistry)
	_, out, err := handleSignIntentAccess(nil, nil, signIntentAccessInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignIntentMark_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := fixedIntentMarkPayload()
	p.Domain = foreignDomain("ReferrerIntentAccess", pinTestRegistry)
	_, out, err := handleSignIntentMark(nil, nil, signIntentMarkInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignIntentSkip_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := fixedIntentSkipPayload()
	p.Domain = foreignDomain("ReferrerIntentAccess", pinTestRegistry)
	_, out, err := handleSignIntentSkip(nil, nil, signIntentSkipInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignTelegramLink_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	p := fixedTelegramPayload()
	p.Domain = foreignDomain("ReferrerTelegramLink", pinTestRegistry)
	_, out, err := handleSignTelegramLink(nil, nil, signTelegramLinkInput{Commitment: p})
	assertDomainRefusal(t, out, err)
}

func TestSignCharge_RefusesForeignDomain(t *testing.T) {
	pinEnv(t)
	in := validChargeInput()
	in.ChainID = 1
	in.SplitRouterAddr = pinTestRouter
	_, out, err := handleSignCharge(nil, nil, in)
	assertDomainRefusal(t, out, err)
}
