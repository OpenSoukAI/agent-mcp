package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestUpdateProduct_SendsOnlyGivenFields pins the partial write (REF-398): an omitted field
// must not appear in the body, or the backend would keep nothing the caller left out.
func TestUpdateProduct_SendsOnlyGivenFields(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusCreated, `{"merchant_id":4,"product_id":"`+validTestProductID+`"}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleUpdateProduct(t.Context(), nil, updateProductInput{
		MerchantID:  "4",
		ProductID:   validTestProductID,
		Name:        strPtr("Sentiment Pro"),
		Description: strPtr(""),
	})
	if err != nil {
		t.Fatalf("update_product: %v", err)
	}
	if got.method != http.MethodPost || got.path != "/v1/merchant/product" {
		t.Errorf("sent %s %s", got.method, got.path)
	}
	var sent map[string]any
	if err := json.Unmarshal(got.body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	want := map[string]any{"merchant_id": float64(4), "product_id": validTestProductID, "name": "Sentiment Pro", "description": ""}
	if len(sent) != len(want) {
		t.Errorf("body = %v, want exactly %v", sent, want)
	}
	for k, v := range want {
		if sent[k] != v {
			t.Errorf("%s = %v, want %v", k, sent[k], v)
		}
	}
	if strings.Join(out.Updated, ",") != "name,description" {
		t.Errorf("updated = %v", out.Updated)
	}
	assertSignedFor(t, got, merchantKeyAddr(t, "4"))
}

func TestUpdateProduct_RefusesBeforeSending(t *testing.T) {
	cases := []struct {
		name string
		in   updateProductInput
		want string
	}{
		{"nothing", updateProductInput{}, "nothing to update"},
		{"empty name", updateProductInput{Name: strPtr(" ")}, "name cannot be cleared"},
		{"cleared referral", updateProductInput{EndpointURL: strPtr("")}, "endpoint_url"},
		{"relative referral", updateProductInput{EndpointURL: strPtr("/v1/ref")}, "endpoint_url"},
		{"bad public", updateProductInput{PublicEndpointURL: strPtr("ftp://x.example/a")}, "public_endpoint_url"},
		{"same routes", updateProductInput{EndpointURL: strPtr("https://x.example/a"), PublicEndpointURL: strPtr("HTTPS://X.example/a/")}, "must differ"},
		{"bad product id", updateProductInput{ProductID: "0xab", Name: strPtr("n")}, "product_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got capturedRequest
			srv := fakeBackend(t, http.StatusCreated, `{}`, &got)
			useFakeBackend(t, srv, "4")
			tc.in.MerchantID = "4"
			if tc.in.ProductID == "" {
				tc.in.ProductID = validTestProductID
			}
			_, _, err := handleUpdateProduct(t.Context(), nil, tc.in)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
			if got.path != "" {
				t.Errorf("a request was sent: %s", got.path)
			}
		})
	}
}

// Clearing the public endpoint is allowed: it unpairs the routes.
func TestUpdateProduct_EmptyPublicEndpointUnpairs(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusCreated, `{}`, &got)
	useFakeBackend(t, srv, "4")
	if _, _, err := handleUpdateProduct(t.Context(), nil, updateProductInput{MerchantID: "4", ProductID: validTestProductID, PublicEndpointURL: strPtr("")}); err != nil {
		t.Fatalf("update_product: %v", err)
	}
	var sent map[string]any
	_ = json.Unmarshal(got.body, &sent)
	if v, ok := sent["public_endpoint_url"]; !ok || v != "" {
		t.Errorf("public_endpoint_url = %v (present %v), want \"\" sent", v, ok)
	}
}

func TestUpdateProduct_ForbiddenNamesTheOwnerRule(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusForbidden, `{"error":"caller does not own this merchant"}`, &got)
	useFakeBackend(t, srv, "4")
	_, _, err := handleUpdateProduct(t.Context(), nil, updateProductInput{MerchantID: "4", ProductID: validTestProductID, Category: strPtr("weather")})
	if err == nil || !strings.Contains(err.Error(), "PRODUCT_MANAGER") {
		t.Fatalf("err = %v, want the owner-only explanation", err)
	}
}

func TestSameURL(t *testing.T) {
	if !sameURL("https://API.example.com/v1/a/", "https://api.example.com/v1/a") {
		t.Error("scheme/host case and a trailing slash should not matter")
	}
	if sameURL("https://x.io/A", "https://x.io/a") {
		t.Error("the path keeps its case, as the backend's resource key does")
	}
}
