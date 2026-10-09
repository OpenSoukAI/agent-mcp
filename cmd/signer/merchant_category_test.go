package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// vocabServer serves a GET /v1/product-categories with two slugs, and counts its calls.
func vocabServer(t *testing.T, status int) *int {
	t.Helper()
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/product-categories" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"kinds":[],"categories":[{"slug":"chain.token.price","kind":"lookup"},{"slug":"chain.rpc","kind":"rpc"}]}`))
	}))
	t.Cleanup(srv.Close)
	t.Setenv("REFERRER_API_URL", srv.URL)
	return &calls
}

func addProductWith(category string) addProductInput {
	return addProductInput{
		MerchantID: "4", ProductID: validTestProductID, CommissionBps: 500,
		EndpointURL: "https://shop.example/buy", Name: "Widget", Category: category,
	}
}

// REF-447: a category outside the vocabulary is refused before addProduct, not after it.
func TestAddProduct_CategoryCheckedBeforeTheChain(t *testing.T) {
	installMerchantKey(t)

	for _, tc := range []struct {
		desc, category string
		status         int
		wantChain      bool
		wantCalls      int
		mention        string
	}{
		{"vocabulary slug", "chain.rpc", http.StatusOK, true, 1, ""},
		{"no category", "", http.StatusOK, true, 0, ""},
		{"legacy free text", "RPC Provider", http.StatusOK, false, 1, "not in the product category vocabulary"},
		{"vocabulary unreachable", "chain.rpc", http.StatusInternalServerError, false, 1, "could not check category"},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			calls := vocabServer(t, tc.status)
			_, _, err := handleAddProduct(t.Context(), nil, addProductWith(tc.category))
			if err == nil {
				t.Fatal("want an error: either the refusal or the BASE_RPC_URL dial")
			}
			if got := strings.Contains(err.Error(), errNoRPC); got != tc.wantChain {
				t.Fatalf("reached the chain = %v, want %v: %v", got, tc.wantChain, err)
			}
			if tc.mention != "" && (!strings.Contains(err.Error(), tc.mention) || !strings.Contains(err.Error(), "nothing was sent")) {
				t.Errorf("error does not say %q and that nothing was sent: %v", tc.mention, err)
			}
			if *calls != tc.wantCalls {
				t.Errorf("vocabulary fetched %d times, want %d", *calls, tc.wantCalls)
			}
		})
	}
}

func TestAddProduct_RefusalSuggestsSlugs(t *testing.T) {
	installMerchantKey(t)
	vocabServer(t, http.StatusOK)
	_, _, err := handleAddProduct(t.Context(), nil, addProductWith("gadgets"))
	if err == nil || !strings.Contains(err.Error(), "chain.token.price, chain.rpc") {
		t.Errorf("refusal does not suggest slugs: %v", err)
	}
}
