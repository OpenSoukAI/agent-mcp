package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ── Reused-authorization detection on the pay retry path (REF-265 item 2) ───────
//
// A retry with the same idempotency_key derives the same ERC-3009 nonce, so the second
// receiveWithAuthorization reverts and the wallet is charged at most once (REF-193). That works;
// the revert just used to reach the caller as a raw selector inside a facilitator 402:
//
//	{"error":"... execution reverted: custom error 0x3d22f6b8: 0000…"}
//
// REF-193 §C tells the runner to catch it, treat it as already-paid, and mark the intent executed.
// Matching that needed a hex constant REF-193 never states. Since REF-364 the facilitator keeps the
// revert in its log and reports errorReason "authorization_used"; the revert matchers serve older ones.

// alreadyPaidToken leads the error message so a runner can prefix-match one stable string instead
// of a selector. It is the REF-193 §C contract; do not reword it.
const alreadyPaidToken = "already_paid"

// alreadyPaidAdvice explains the state the caller is actually in.
const alreadyPaidAdvice = "this idempotency_key was already used to pay, so the authorization " +
	"nonce is spent and the wallet was charged at most once. The purchase stands: mark the intent " +
	"executed rather than retrying. A retry with a NEW idempotency_key would pay a second time."

// realUSDCAuthReused is Circle FiatTokenV2_2's require string for a replayed nonce.
//
// The two rails revert differently: MockUSDC uses a custom error, a divergence its own doc block
// calls deliberate, while real USDC uses a string. Verified against Base mainnet USDC at block
// 50,900,000 — replaying a consumed authorization returns Error(string) "FiatTokenV2: authorization
// is used or canceled". Matching the selector alone would work on anvil only.
const realUSDCAuthReused = "authorization is used or canceled"

// facilitatorAuthUsedReason is the facilitator's errorReason for a consumed authorization (REF-364);
// merchants forward it in the phase-2 body.
const facilitatorAuthUsedReason = "authorization_used"

// authReusedRevertTable holds the MockUSDC custom error. The selector is derived from the
// signature by newRevertTable, so there is no hex to drift from the contract.
var authReusedRevertTable = newRevertTable(map[string]string{
	"AuthNonceAlreadyUsed(address,bytes32)": alreadyPaidAdvice,
})

// classifyAuthReused reports whether a facilitator failure body means the payment already
// happened, on either rail. Anything else falls through to the raw error: misreporting a genuine
// failure as a completed purchase is worse than an undecoded selector.
func classifyAuthReused(body string) (advice string, ok bool) {
	var r struct {
		ErrorReason string `json:"errorReason"`
	}
	if json.Unmarshal([]byte(body), &r) == nil && r.ErrorReason == facilitatorAuthUsedReason {
		return alreadyPaidAdvice, true
	}
	if strings.Contains(body, realUSDCAuthReused) {
		return alreadyPaidAdvice, true
	}
	return authReusedRevertTable.lookupText(body)
}

// alreadyPaidError formats the reply, keeping the facilitator's own body so the evidence survives.
func alreadyPaidError(status int, body, advice string) error {
	return fmt.Errorf("%s: %s (facilitator returned %d: %s)", alreadyPaidToken, advice, status, body)
}

// phase2Failure turns a non-200 facilitator response into the error the caller sees.
//
// A reused idempotency_key means the wallet was ALREADY charged, not that the purchase failed
// (REF-265 item 2), so that case gets the named token. Everything else keeps the raw status and
// body: misreporting a genuine failure as a completed purchase is worse than an undecoded selector.
func phase2Failure(status int, body string) error {
	if advice, ok := classifyAuthReused(body); ok {
		return alreadyPaidError(status, body, advice)
	}
	return fmt.Errorf("phase 2: expected 200, got %d: %s", status, body)
}
