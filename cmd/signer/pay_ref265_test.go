package main

import (
	"strings"
	"testing"
)

// ── Item 1: next_steps must be reachable by the caller it is handed to ──────────────────
//
// pay_for_product without agent_id — the documented agent-less path — returned next_steps
// byte-identical to the agent-bound case, telling the caller to use cast_review_votes. That tool
// REQUIRES agent_id, so on this path the advice cannot be satisfied at all:
//
//	ERROR validating "arguments": validating root: required: missing properties: ["agent_id"]
//
// Structural, not a likelihood — proven by the schema. The handler already refuses inline
// submit_votes for exactly this reason, so the knowledge existed and simply was not reflected in
// the guidance. bind_escrow is the real next step and next_steps never mentioned it.

func TestPayNextSteps_AgentLessPointsAtBind(t *testing.T) {
	got := payNextSteps(true)

	if strings.Contains(got, "cast_review_votes") && !strings.Contains(got, "bind_escrow") {
		t.Fatalf("agent-less next_steps recommends cast_review_votes and never mentions "+
			"bind_escrow:\n%s\n\ncast_review_votes requires agent_id, which this caller does not "+
			"have — the advice cannot be followed.", got)
	}
	if !strings.Contains(got, "bind_escrow") {
		t.Errorf("agent-less next_steps must name bind_escrow:\n%s", got)
	}
	// It must also say WHY voting is unavailable, or the caller reads the omission as an oversight
	// and calls cast_review_votes anyway.
	if !strings.Contains(got, "agent_id") {
		t.Errorf("agent-less next_steps should say voting needs an agent_id:\n%s", got)
	}
}

func TestPayNextSteps_AgentBoundIsUnchanged(t *testing.T) {
	got := payNextSteps(false)
	if got != payVoteReminder {
		t.Errorf("the agent-bound path must keep its existing nudge verbatim:\ngot:  %s\nwant: %s",
			got, payVoteReminder)
	}
	if !strings.Contains(got, "cast_review_votes") {
		t.Error("agent-bound next_steps must still point at cast_review_votes")
	}
}

// ── Item 2: a reused authorization must be identifiable without a hex constant ──────────
//
// Two pay_for_product calls with the same idempotency_key behave correctly — exactly 1.0 USDC
// moves, the second reverts, the at-most-once guarantee holds. But the second call returned the
// revert as a raw selector inside a facilitator 402:
//
//	{"error":"settle: route tx: Route tx: execution reverted: custom error 0x3d22f6b8: 0000…"}
//
// REF-193 §C instructs the runner to "catch that revert, treat it as already-paid, and mark the
// intent executed". A runner matching on text cannot match that, and hardcoding 0x3d22f6b8 means a
// magic constant REF-193's guidance never states.
//
// The two rails revert DIFFERENTLY, which the ticket did not account for. MockUSDC uses a custom
// error; real Circle USDC uses a require string — a deliberate, documented divergence
// (contracts/src/MockUSDC.sol). Verified empirically against Base mainnet USDC at block 50,900,000:
// a replayed authorization returns Error(string) "FiatTokenV2: authorization is used or canceled".
// Decoding only the selector would make the runner contract implementable on anvil alone.

func TestClassifyAuthReused_BothRails(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{
			// MockUSDC / anvil, verbatim from the finding.
			name: "mock usdc custom error selector",
			body: `{"error":"settle: route tx: Route tx: execution reverted: custom error ` +
				`0x3d22f6b8: 000000000000000000000000976ea74026e726554db657fa54763abd0c3a0aa9` +
				`a74bc243d5ab484ed80c7e59202d2f49916967baaf660b6693bd80906de8116c"}`,
		},
		{
			// Real Circle USDC, verified on a Base mainnet fork.
			name: "real usdc require string",
			body: `{"error":"settle: route tx: Route tx: execution reverted: ` +
				`FiatTokenV2: authorization is used or canceled"}`,
		},
		{
			// REF-364: the facilitator keeps the revert in its log and reports this reason instead.
			name: "facilitator authorization_used reason (REF-364)",
			body: `{"success":false,"errorReason":"authorization_used","errorMessage":"this payment authorization was already used or cancelled; this request moved no funds — deliver only if you hold a successful settlement transaction for it"}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			advice, ok := classifyAuthReused(tc.body)
			if !ok {
				t.Fatalf("not recognised as a reused authorization:\n%s", tc.body)
			}
			// The advice has to tell the runner the money is settled, not lost.
			for _, want := range []string{"idempotency_key", "at most once"} {
				if !strings.Contains(advice, want) {
					t.Errorf("advice missing %q:\n%s", want, advice)
				}
			}
		})
	}
}

// Anything else must fall through to the existing raw error, or a real failure is misreported as a
// completed purchase — the one outcome worse than an undecoded selector.
func TestClassifyAuthReused_IgnoresOtherFailures(t *testing.T) {
	for _, body := range []string{
		`{"error":"settle: route tx: Route tx: execution reverted: custom error 0xdeadbeef: 00"}`,
		`{"error":"insufficient balance"}`,
		`{"error":"execution reverted: FiatTokenV2: invalid signature"}`,
		`{"error":"ProductNotActive()"}`,
		`{"success":false,"errorReason":"settle_failed","errorMessage":"settlement failed; this request moved no funds"}`,
		`{"success":false,"errorReason":"settle_pending","transaction":"0xabc"}`,
		`{"success":false,"errorReason":"lookup_unavailable"}`,
		`{"error":"errorReason authorization_used mentioned in prose is not the field"}`,
		`not json authorization_used`,
		"",
	} {
		if advice, ok := classifyAuthReused(body); ok {
			t.Errorf("body %q wrongly classified as already-paid: %s", body, advice)
		}
	}
}

// The selector must be DERIVED from the signature, not hardcoded — that is what stops it drifting
// from the contract. 0x3d22f6b8 is the value the finding observed.
func TestAuthReusedSelectorMatchesTheContract(t *testing.T) {
	if _, ok := authReusedRevertTable["3d22f6b8"]; !ok {
		t.Fatalf("AuthNonceAlreadyUsed(address,bytes32) does not hash to 3d22f6b8; table = %v",
			authReusedRevertTable)
	}
}

// The runner needs one stable token to match on across both rails.
func TestAlreadyPaidToken_IsStableAndLeading(t *testing.T) {
	if alreadyPaidToken != "already_paid" {
		t.Errorf("alreadyPaidToken = %q — REF-193 §C's runner contract keys on this string",
			alreadyPaidToken)
	}
	err := alreadyPaidError(402, "whatever the facilitator said", "advice here")
	if !strings.HasPrefix(err.Error(), alreadyPaidToken+":") {
		t.Errorf("the token must lead the message so a prefix match works:\n%s", err)
	}
	// The raw body still has to survive, or an operator loses the evidence on the one path where
	// something surprising may be hiding.
	if !strings.Contains(err.Error(), "whatever the facilitator said") {
		t.Errorf("the facilitator's own body must be preserved:\n%s", err)
	}
}
