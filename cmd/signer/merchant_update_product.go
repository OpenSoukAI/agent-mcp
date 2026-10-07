package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── update_product ──────────────────────────────────────────────────────────────
//
// A partial update of a product's backend metadata (REF-398): POST /v1/merchant/product with
// only the fields given. No transaction — commission and the active flag live on-chain and
// have their own tools. The backend owns the write: the owner or a PRODUCT_MANAGER (REF-446).

// Pointers so an omitted field stays distinct from "": an omitted field keeps its stored
// value, and "" clears it.
type updateProductInput struct {
	MerchantID        string  `json:"merchant_id"` // decimal; the merchant's own ERC-8004 id
	ProductID         string  `json:"product_id"`  // 0x-prefixed 32-byte hex
	Name              *string `json:"name,omitempty"`
	Description       *string `json:"description,omitempty"`         // "" clears it
	Category          *string `json:"category,omitempty"`            // a doc-22 slug; "" clears it
	EndpointURL       *string `json:"endpoint_url,omitempty"`        // the referral endpoint; replaceable, never cleared
	PublicEndpointURL *string `json:"public_endpoint_url,omitempty"` // merchant-only; "" unpairs it
}

type updateProductOutput struct {
	MerchantID string `json:"merchant_id"`
	ProductID  string `json:"product_id"`
	// Updated names the fields sent. The backend answers with no copy of what it stored.
	Updated []string `json:"updated"`
}

func handleUpdateProduct(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in updateProductInput,
) (*sdkmcp.CallToolResult, updateProductOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, updateProductOutput{}, err
	}
	restID, err := merchantIDForREST(merchantID)
	if err != nil {
		return nil, updateProductOutput{}, err
	}
	if _, err := parseProductID(in.ProductID); err != nil {
		return nil, updateProductOutput{}, err
	}

	// The backend would store an empty name; nothing reads a product well without one.
	if in.Name != nil && strings.TrimSpace(*in.Name) == "" {
		return nil, updateProductOutput{}, fmt.Errorf("name cannot be cleared; omit it to keep the current name")
	}
	if in.EndpointURL != nil && !isHTTPURL(*in.EndpointURL) {
		return nil, updateProductOutput{}, fmt.Errorf("endpoint_url must be an absolute http(s) URL; the referral endpoint can be replaced but not cleared")
	}
	if in.PublicEndpointURL != nil && *in.PublicEndpointURL != "" && !isHTTPURL(*in.PublicEndpointURL) {
		return nil, updateProductOutput{}, fmt.Errorf("public_endpoint_url must be an absolute http(s) URL, or \"\" to unpair it")
	}
	if in.EndpointURL != nil && in.PublicEndpointURL != nil && *in.PublicEndpointURL != "" && sameURL(*in.EndpointURL, *in.PublicEndpointURL) {
		return nil, updateProductOutput{}, fmt.Errorf("public_endpoint_url and endpoint_url must differ: the referral endpoint is a separate copy of the public one")
	}

	req := map[string]any{"merchant_id": restID, "product_id": in.ProductID}
	var updated []string
	for _, f := range []struct {
		key string
		v   *string
	}{
		{"name", in.Name},
		{"description", in.Description},
		{"category", in.Category},
		{"endpoint_url", in.EndpointURL},
		{"public_endpoint_url", in.PublicEndpointURL},
	} {
		if f.v != nil {
			req[f.key] = *f.v
			updated = append(updated, f.key)
		}
	}
	if len(updated) == 0 {
		return nil, updateProductOutput{}, fmt.Errorf("nothing to update: pass name, description, category, endpoint_url or public_endpoint_url")
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, updateProductOutput{}, fmt.Errorf("encode request: %w", err)
	}
	if _, err := callAuthedRaw(ctx, "update_product", http.MethodPost, "/v1/merchant/product",
		body, merchantID, map[int]string{
			http.StatusNotFound:   "the product is not on-chain for this merchant — check product_id, or add it first with add_product",
			http.StatusForbidden:  "the signing key neither owns the merchant identity nor holds PRODUCT_MANAGER for it",
			http.StatusConflict:   "this merchant has no backend record — call activate_merchant first",
			http.StatusBadRequest: "the backend rejected a field; the message above names which one",
		}); err != nil {
		return nil, updateProductOutput{}, err
	}

	return nil, updateProductOutput{MerchantID: merchantID.String(), ProductID: in.ProductID, Updated: updated}, nil
}

// checkEndpointPair validates a referral endpoint and an optional public one before anything
// is sent: both absolute http(s), and not the same URL.
func checkEndpointPair(referral, public string) error {
	if !isHTTPURL(referral) {
		return fmt.Errorf("endpoint_url must be an absolute http(s) URL (the product's referral x402 endpoint)")
	}
	if public == "" {
		return nil
	}
	if !isHTTPURL(public) {
		return fmt.Errorf("public_endpoint_url must be an absolute http(s) URL")
	}
	if sameURL(referral, public) {
		return fmt.Errorf("public_endpoint_url and endpoint_url must differ: the referral endpoint is a separate copy of the public one")
	}
	return nil
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(strings.TrimSpace(s))
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

// sameURL compares as the backend keys resources: scheme and host case-insensitive, a trailing
// slash ignored, the path's case kept.
func sameURL(a, b string) bool {
	norm := func(s string) string {
		u, err := url.Parse(strings.TrimSpace(s))
		if err != nil {
			return strings.TrimSpace(s)
		}
		u.Scheme = strings.ToLower(u.Scheme)
		u.Host = strings.ToLower(u.Host)
		u.Path = strings.TrimSuffix(u.Path, "/")
		return u.String()
	}
	return norm(a) == norm(b)
}
