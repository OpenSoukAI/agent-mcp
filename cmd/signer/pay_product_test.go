package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	x402types "github.com/x402-foundation/x402/go/types"
)

// Merchant-wide commission (REF-317): one ref link pays for any product of the same merchant on
// the x402 rail. The agent names the product it wants; the merchant's 402 names the product it
// sells; settlement records what the 402 says.

const (
	tokenProductHex   = "0x00000000000000000000000000000000000000000000000000000000000000aa" // validTestToken
	siblingProductHex = "0x00000000000000000000000000000000000000000000000000000000000000bb"
	otherProductHex   = "0x00000000000000000000000000000000000000000000000000000000000000cc"
)

func reqWithExtra(extra map[string]any) x402types.PaymentRequirements {
	return x402types.PaymentRequirements{Scheme: "exact", Amount: "1000000", Extra: extra}
}

func TestSettledProductFrom402(t *testing.T) {
	cases := []struct {
		name        string
		extra       map[string]any
		intended    string
		wantSettled string
		wantWarn    bool
		wantErr     string
	}{
		{"absent, buying token product", map[string]any{"name": "USDC"}, tokenProductHex, tokenProductHex, false, ""},
		{"absent, buying sibling: falls back with warning", map[string]any{"name": "USDC"}, siblingProductHex, tokenProductHex, true, ""},
		{"names the sibling we asked for", map[string]any{"productId": siblingProductHex}, siblingProductHex, siblingProductHex, false, ""},
		{"names the token product we asked for", map[string]any{"productId": tokenProductHex}, tokenProductHex, tokenProductHex, false, ""},
		{"case-insensitive match", map[string]any{"productId": strings.ToUpper(siblingProductHex[2:])}, siblingProductHex, siblingProductHex, false, ""},
		{"names another product than asked", map[string]any{"productId": otherProductHex}, siblingProductHex, "", false, "402 names product"},
		{"names another product at the token's own endpoint", map[string]any{"productId": otherProductHex}, tokenProductHex, "", false, "402 names product"},
		{"empty string behaves as absent", map[string]any{"productId": ""}, siblingProductHex, tokenProductHex, true, ""},
		{"non-string is rejected", map[string]any{"productId": 42}, siblingProductHex, "", false, "extra.productId"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settled, warn, err := settledProductFrom402(reqWithExtra(tc.extra), tc.intended, tokenProductHex)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.EqualFold(settled, tc.wantSettled) {
				t.Errorf("settled: got %s, want %s", settled, tc.wantSettled)
			}
			if (warn != "") != tc.wantWarn {
				t.Errorf("warning: got %q, wantWarn=%v", warn, tc.wantWarn)
			}
		})
	}
}

// productLookupServer answers GET /v1/merchant/product like the backend does, recording the query.
func productLookupServer(t *testing.T, status int, body string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	queries := []string{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/merchant/product" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		queries = append(queries, r.URL.RawQuery)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

func TestResolvePayTarget_EmptyOrTokenProduct_NoLookup(t *testing.T) {
	srv, queries := productLookupServer(t, http.StatusOK, `{}`)
	tok := validTestToken()
	for _, pid := range []string{"", tokenProductHex, strings.ToUpper(tokenProductHex[2:])} {
		endpoint, intended, err := resolvePayTarget(context.Background(), srv.Client(), srv.URL, tok, pid)
		if err != nil {
			t.Fatalf("product_id %q: %v", pid, err)
		}
		if endpoint != tok.MerchantEndpoint {
			t.Errorf("product_id %q: endpoint %s, want token endpoint %s", pid, endpoint, tok.MerchantEndpoint)
		}
		if !strings.EqualFold(intended, tok.ProductID) {
			t.Errorf("product_id %q: intended %s, want token product", pid, intended)
		}
	}
	if len(*queries) != 0 {
		t.Errorf("token product must not be looked up, got %d lookups", len(*queries))
	}
}

func TestResolvePayTarget_Sibling_UsesCatalogueEndpoint(t *testing.T) {
	srv, queries := productLookupServer(t, http.StatusOK,
		`{"merchant_id":3,"product_id":"`+siblingProductHex+`","active":true,"endpoint_url":"https://merchant.example/buy-b"}`)
	endpoint, intended, err := resolvePayTarget(context.Background(), srv.Client(), srv.URL, validTestToken(), siblingProductHex)
	if err != nil {
		t.Fatalf("resolvePayTarget: %v", err)
	}
	if endpoint != "https://merchant.example/buy-b" {
		t.Errorf("endpoint: got %s, want the sibling's endpoint_url", endpoint)
	}
	if intended != siblingProductHex {
		t.Errorf("intended: got %s, want sibling", intended)
	}
	if len(*queries) != 1 || !strings.Contains((*queries)[0], "merchant_id=3") || !strings.Contains((*queries)[0], "product_id="+siblingProductHex) {
		t.Errorf("lookup must be under the token's merchant for the requested product, got %v", *queries)
	}
}

func TestResolvePayTarget_UnknownProduct_Rejected(t *testing.T) {
	srv, _ := productLookupServer(t, http.StatusNotFound, `{"error":"product not found"}`)
	_, _, err := resolvePayTarget(context.Background(), srv.Client(), srv.URL, validTestToken(), siblingProductHex)
	if err == nil || !strings.Contains(err.Error(), "not a listed product of merchant 3") {
		t.Fatalf("want 'not a listed product of merchant 3', got %v", err)
	}
}

func TestResolvePayTarget_NoEndpoint_Rejected(t *testing.T) {
	srv, _ := productLookupServer(t, http.StatusOK, `{"active":true,"endpoint_url":""}`)
	_, _, err := resolvePayTarget(context.Background(), srv.Client(), srv.URL, validTestToken(), siblingProductHex)
	if err == nil || !strings.Contains(err.Error(), "no registered payment endpoint") {
		t.Fatalf("want 'no registered payment endpoint', got %v", err)
	}
}

func TestResolvePayTarget_MalformedID_RejectedWithoutLookup(t *testing.T) {
	srv, queries := productLookupServer(t, http.StatusOK, `{}`)
	for _, bad := range []string{"0x0102", "zz", siblingProductHex + "00"} {
		_, _, err := resolvePayTarget(context.Background(), srv.Client(), srv.URL, validTestToken(), bad)
		if err == nil || !strings.Contains(err.Error(), "product_id") {
			t.Errorf("%q: want a product_id validation error, got %v", bad, err)
		}
	}
	if len(*queries) != 0 {
		t.Errorf("malformed ids must be rejected before any lookup, got %d", len(*queries))
	}
}

// ── wiring ────────────────────────────────────────────────────────────────────

// crossProductEnv is payTestEnv plus a sibling product: the fake backend serves the catalogue
// lookup, and the merchant has a second endpoint /buy-b whose 402 carries extra.productId =
// asserted. Phase 2 at either endpoint fails with 502 so the handler stops before any chain
// work. Returns the ref link and the ordered list of "METHOD path [paid]" the fake saw.
func crossProductEnv(t *testing.T, asserted string) (string, func() []string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	hits := []string{}
	record := func(r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		h := r.Method + " " + r.URL.Path
		if r.Header.Get("PAYMENT-SIGNATURE") != "" {
			h += " [paid]"
		}
		hits = append(hits, h)
	}
	requirements := func(extra map[string]any) map[string]any {
		return map[string]any{
			"x402Version": 2,
			"accepts": []map[string]any{{
				"scheme": "exact", "network": "eip155:84532", "amount": "1000000",
				"asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
				"payTo": "0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E", "maxTimeoutSeconds": 600,
				"extra": extra,
			}},
		}
	}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r)
		switch {
		case r.URL.Path == "/.well-known/opensouk":
			_, _ = w.Write([]byte(`{"attestationPubKey":"` + hexKey(pub) + `"}`))
		case r.URL.Path == "/v1/merchant/product":
			if r.URL.Query().Get("product_id") != siblingProductHex {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write([]byte(`{"active":true,"endpoint_url":"` + srv.URL + `/buy-b"}`))
		case (r.URL.Path == "/buy" || r.URL.Path == "/buy-b") && r.Header.Get("PAYMENT-SIGNATURE") == "":
			extra := map[string]any{"name": "USDC", "version": "2"}
			if asserted != "" && r.URL.Path == "/buy-b" {
				extra["productId"] = asserted
			}
			w.WriteHeader(http.StatusPaymentRequired)
			_ = json.NewEncoder(w).Encode(requirements(extra))
		case r.URL.Path == "/buy" || r.URL.Path == "/buy-b":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"error":"stop here"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	tok := validTestToken()
	tok.MerchantEndpoint = srv.URL + "/buy"
	t.Setenv("BASE_RPC_URL", srv.URL+"/rpc")
	t.Setenv("CHAIN_ID", "84532")
	t.Setenv("ATTESTATION_ORIGIN", srv.URL)
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	prev := signerKeys
	signerKeys = &keystore{fallback: newLocalSigner(key)}
	t.Cleanup(func() { signerKeys = prev })

	return srv.URL + "/r/" + signTestToken(t, priv, tok), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), hits...)
	}
}

func TestPayForProduct_SiblingProduct_PaysAtItsEndpoint(t *testing.T) {
	refLink, hits := crossProductEnv(t, siblingProductHex)
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex,
	})
	if err == nil || !strings.Contains(err.Error(), "stop here") {
		t.Fatalf("expected to reach phase 2 at the sibling endpoint and stop there, got %v", err)
	}
	seen := strings.Join(hits(), "\n")
	for _, want := range []string{"GET /v1/merchant/product", "POST /buy-b\n", "POST /buy-b [paid]"} {
		if !strings.Contains(seen+"\n", want) {
			t.Errorf("missing %q in requests:\n%s", want, seen)
		}
	}
	if strings.Contains(seen, "POST /buy\n") || strings.Contains(seen, "POST /buy [paid]") {
		t.Errorf("the token's own endpoint must not be touched when buying a sibling:\n%s", seen)
	}
}

func TestPayForProduct_402NamesOtherProduct_RefusesBeforePaying(t *testing.T) {
	refLink, hits := crossProductEnv(t, otherProductHex)
	_, _, err := handlePayForProduct(context.Background(), nil, payForProductInput{
		RefLink: refLink, AgentID: "12", ProductID: siblingProductHex,
	})
	if err == nil || !strings.Contains(err.Error(), "402 names product") {
		t.Fatalf("want refusal naming the 402 mismatch, got %v", err)
	}
	for _, h := range hits() {
		if strings.HasSuffix(h, "[paid]") {
			t.Fatalf("no payment may be submitted after a product mismatch, saw %q", h)
		}
	}
}
