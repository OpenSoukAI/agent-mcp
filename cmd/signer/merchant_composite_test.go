package main

import (
	"math/big"
	"net/http"
	"strings"
	"testing"
)

// The composites' happy paths need a chain (they read before writing), so those live in
// merchant_live_test.go. What is unit-testable is everything around the chain: how a 409 is
// folded into success, what a post-chain sync failure tells the agent, and that inputs are
// rejected before anything is sent.

// TestRegisterIdentity_ConflictIsSuccess is the property that makes activate_merchant
// re-runnable. Both registration endpoints answer 409 when the row already exists, and a
// resumed activation hits that on the step which had actually succeeded.
func TestRegisterIdentity_ConflictIsSuccess(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusConflict, `{"error":"agent already registered"}`, &got)
	useFakeBackend(t, srv, "4")

	status, err := registerIdentity(t.Context(), "activate_merchant", "/v1/agent/register",
		map[string]any{"agent_id": int64(4)}, mustBigInt(t, "4"), "agent")
	if err != nil {
		t.Fatalf("a 409 was reported as a failure, so a resumed activation can never finish: %v", err)
	}
	if status != "already_registered" {
		t.Errorf("status = %q, want already_registered", status)
	}
}

// TestRegisterIdentity_CreatedIsSuccess pins the other half: these endpoints answer 201, not
// 200. A client that accepted only 200 would call every successful registration a failure.
func TestRegisterIdentity_CreatedIsSuccess(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusCreated, `{"agent_id":4,"owner_address":"0xabc"}`, &got)
	useFakeBackend(t, srv, "4")

	status, err := registerIdentity(t.Context(), "activate_merchant", "/v1/agent/register",
		map[string]any{"agent_id": int64(4)}, mustBigInt(t, "4"), "agent")
	if err != nil {
		t.Fatalf("a 201 was reported as a failure: %v", err)
	}
	if status != "created" {
		t.Errorf("status = %q, want created", status)
	}
}

func TestRegisterIdentity_OtherFailuresPropagate(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "not active on-chain"}, // merchant-specific 403 advice
		{http.StatusInternalServerError, "500"},
	} {
		var got capturedRequest
		srv := fakeBackend(t, tc.status, `{"error":"nope"}`, &got)
		useFakeBackend(t, srv, "4")

		_, err := registerIdentity(t.Context(), "activate_merchant", "/v1/merchant/register",
			map[string]any{"merchant_id": int64(4)}, mustBigInt(t, "4"), "merchant")
		if err == nil {
			t.Fatalf("status %d was swallowed", tc.status)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d: error = %v, want it to mention %q", tc.status, err, tc.want)
		}
	}
}

// TestRegisterIdentity_MerchantForbiddenNamesBothCauses: /merchant/register 403s both when
// the caller is not the owner AND when the merchant is inactive on-chain. An agent told only
// "forbidden" will go and check the wrong one.
func TestRegisterIdentity_MerchantForbiddenNamesBothCauses(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusForbidden, `{"error":"merchant not active on-chain"}`, &got)
	useFakeBackend(t, srv, "4")

	_, err := registerIdentity(t.Context(), "activate_merchant", "/v1/merchant/register",
		map[string]any{"merchant_id": int64(4)}, mustBigInt(t, "4"), "merchant")
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "does not own") || !strings.Contains(msg, "not active on-chain") {
		t.Errorf("403 advice does not name both causes: %v", err)
	}
}

// TestSyncFailedAfterChain_TellsTheAgentGasIsSpent covers the failure this design exists
// for. Without the state and the instruction, an agent either gives up on a merchant it has
// already paid to activate, or goes looking for a way to undo a mined transaction.
func TestSyncFailedAfterChain_TellsTheAgentGasIsSpent(t *testing.T) {
	err := syncFailedAfterChain("0xdeadbeef", errRegisterFailed)

	msg := err.Error()
	for _, want := range []string{"0xdeadbeef", "SUCCEEDED", "gas is spent", "activate_merchant again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("sync failure does not mention %q: %s", want, msg)
		}
	}
	// The underlying error has to survive; it says WHAT failed.
	if !strings.Contains(msg, errRegisterFailed.Error()) {
		t.Errorf("the wrapped cause was dropped: %s", msg)
	}
}

// When nothing was sent, saying gas was spent would be a lie that sends the agent looking
// for a transaction that does not exist.
func TestSyncFailedAfterChain_NoTxIsNotReportedAsSpent(t *testing.T) {
	msg := syncFailedAfterChain("", errRegisterFailed).Error()

	if strings.Contains(msg, "gas is spent") {
		t.Errorf("no transaction was sent but the error claims gas was spent: %s", msg)
	}
	if !strings.Contains(msg, "already active") {
		t.Errorf("the error does not explain why no transaction was sent: %s", msg)
	}
}

// TestProductSyncFailed_NamesTheSplitState: a product on-chain without backend metadata can
// take payments and cannot be found. Both halves of that have to be said, and so does the
// fact that repeating the call is the fix — addProduct alone would revert
// ProductAlreadyExists, which looks like a dead end.
func TestProductSyncFailed_NamesTheSplitState(t *testing.T) {
	msg := productSyncFailed(addProductOutput{TxHash: "0xfeed"}, errRegisterFailed).Error()

	for _, want := range []string{"0xfeed", "gas is spent", "payable", "NOT discoverable", "add_product again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("product sync failure does not mention %q: %s", want, msg)
		}
	}
}

func TestAddProduct_RequiredFields(t *testing.T) {
	installMerchantKey(t) // configures the chain address but leaves BASE_RPC_URL empty

	const validProduct = validTestProductID

	cases := []struct {
		name  string
		in    addProductInput
		field string
	}{
		{"no endpoint", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 500, Name: "n"}, "endpoint_url"},
		{"no name", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 500, EndpointURL: "https://x/y"}, "name"},
		{"bad product id", addProductInput{MerchantID: "4", ProductID: "0xab", CommissionBps: 500, EndpointURL: "https://x/y", Name: "n"}, "product_id"},
		{"bad rate", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 10001, EndpointURL: "https://x/y", Name: "n"}, "commission_bps"},
		// The backend checks these too, but only after addProduct has spent the gas.
		{"relative endpoint", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 500, EndpointURL: "/buy", Name: "n"}, "endpoint_url"},
		{"bad public", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 500, EndpointURL: "https://x/y", PublicEndpointURL: "x/y", Name: "n"}, "public_endpoint_url"},
		{"same routes", addProductInput{MerchantID: "4", ProductID: validProduct, CommissionBps: 500, EndpointURL: "https://x/y", PublicEndpointURL: "https://X/y/", Name: "n"}, "must differ"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := handleAddProduct(t.Context(), nil, tc.in)
			if err == nil {
				t.Fatal("want an error")
			}
			// Not the dial error: every field must be checked before anything is read or sent.
			if strings.Contains(err.Error(), errNoRPC) {
				t.Fatalf("a missing %s reached the chain: %v", tc.field, err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error does not name %s: %v", tc.field, err)
			}
		})
	}
}

// TestAddProduct_ValidInputReachesTheChain is the control for the test above: it pins where
// a complete call stops, so those assertions are known to be watching a rejected input.
func TestAddProduct_ValidInputReachesTheChain(t *testing.T) {
	installMerchantKey(t)

	_, _, err := handleAddProduct(t.Context(), nil, addProductInput{
		MerchantID:    "4",
		ProductID:     validTestProductID,
		CommissionBps: 500,
		EndpointURL:   "https://shop.example/buy",
		Name:          "Widget",
	})
	if err == nil {
		t.Fatal("want the chain read to fail with BASE_RPC_URL unset")
	}
	if !strings.Contains(err.Error(), errNoRPC) {
		t.Fatalf("a complete call stopped somewhere other than the chain read: %v", err)
	}
}

func TestActivateMerchant_ValidatesBeforeSending(t *testing.T) {
	installMerchantKey(t)

	_, _, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{MerchantID: "-1"})
	if err == nil {
		t.Fatal("want an error for a negative merchant_id")
	}
	if strings.Contains(err.Error(), errNoRPC) {
		t.Fatalf("a malformed merchant_id reached the chain: %v", err)
	}
	if !strings.Contains(err.Error(), "merchant_id") {
		t.Errorf("error does not name merchant_id: %v", err)
	}
}

// TestProductNotFoundTable_ClassifiesOnlyThatSelector guards the branch that turns an absent
// product into "not found" rather than an error. If this table matched anything else, a real
// failure would be read as absence and the tool would send an addProduct that reverts.
func TestProductNotFoundTable_ClassifiesOnlyThatSelector(t *testing.T) {
	got := revertTableSignatures(t, "productNotFoundTable", productNotFoundTable)

	if _, ok := got["ProductNotFound(uint256,bytes32)"]; !ok {
		t.Error("productNotFoundTable does not hold ProductNotFound")
	}
	if len(got) != 1 {
		t.Errorf("productNotFoundTable holds %d entries, want exactly 1 — anything else would be "+
			"misread as an absent product", len(got))
	}
}

var errRegisterFailed = &restStatusError{
	Tool:   "activate_merchant",
	Status: http.StatusInternalServerError,
	Detail: "internal error",
}

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad big int %q", s)
	}
	return v
}

// TestProductMetadataBody_OmitsWhatWasNotGiven: since REF-398 "" clears a stored field, so a
// retry of add_product with fewer fields must not send empties over what an earlier call stored.
func TestProductMetadataBody_OmitsWhatWasNotGiven(t *testing.T) {
	bare := productMetadataBody(4, addProductInput{ProductID: validTestProductID, EndpointURL: "https://x/ref", Name: "n"})
	for _, k := range []string{"description", "category", "public_endpoint_url"} {
		if _, ok := bare[k]; ok {
			t.Errorf("%s sent though not given: %v", k, bare)
		}
	}
	full := productMetadataBody(4, addProductInput{
		ProductID: validTestProductID, EndpointURL: "https://x/ref", Name: "n",
		Description: "d", Category: "weather", PublicEndpointURL: "https://x/pub",
	})
	if full["description"] != "d" || full["category"] != "weather" || full["public_endpoint_url"] != "https://x/pub" || full["endpoint_url"] != "https://x/ref" {
		t.Errorf("full body = %v", full)
	}
}
