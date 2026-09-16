package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	x402types "github.com/x402-foundation/x402/go/types"
)

// Merchant-wide commission (REF-317): a ref link's token pays for any product of the same
// merchant on the x402 rail. The agent names the product it wants (product_id), the catalogue
// says where that product is paid, and the merchant's 402 names the product it actually sells —
// which is what settlement records (backend REF-311).

// normalizeProductID validates a 32-byte hex id (0x prefix optional) and returns it as
// lowercase 0x-hex, so ids from the token, the catalogue and the 402 compare byte-for-byte.
func normalizeProductID(field, s string) (string, error) {
	raw := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	b, err := hex.DecodeString(raw)
	if err != nil {
		return "", fmt.Errorf("%s %q is not hex: %w", field, s, err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("%s %q must be 32 bytes, got %d", field, s, len(b))
	}
	return "0x" + hex.EncodeToString(b), nil
}

// resolvePayTarget picks the endpoint to pay and the product the agent intends to buy. The
// token's own product needs no lookup. A sibling is read from the backend catalogue at apiBase
// — the ref link's host, the same origin the token's attestation key already comes from —
// under the token's merchant, so a product of another merchant simply is not found.
func resolvePayTarget(
	ctx context.Context, client *http.Client, apiBase string, tok decodedAttributionToken, productID string,
) (endpoint, intended string, err error) {
	if strings.TrimSpace(productID) == "" {
		return tok.MerchantEndpoint, tok.ProductID, nil
	}
	want, err := normalizeProductID("product_id", productID)
	if err != nil {
		return "", "", err
	}
	if strings.EqualFold(want, tok.ProductID) {
		return tok.MerchantEndpoint, tok.ProductID, nil
	}

	q := url.Values{"merchant_id": {tok.MerchantID}, "product_id": {want}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(apiBase, "/")+"/v1/merchant/product?"+q.Encode(), nil)
	if err != nil {
		return "", "", fmt.Errorf("build product lookup: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("product lookup: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return "", "", fmt.Errorf("product %s is not a listed product of merchant %s (the ref link's merchant)", want, tok.MerchantID)
	default:
		return "", "", fmt.Errorf("product lookup: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var prod struct {
		Active      bool   `json:"active"`
		EndpointURL string `json:"endpoint_url"`
	}
	if err := json.Unmarshal(body, &prod); err != nil {
		return "", "", fmt.Errorf("parse product lookup: %w", err)
	}
	if !prod.Active {
		return "", "", fmt.Errorf("product %s is not a listed product of merchant %s (the ref link's merchant)", want, tok.MerchantID)
	}
	if strings.TrimSpace(prod.EndpointURL) == "" {
		return "", "", fmt.Errorf("product %s has no registered payment endpoint; the merchant must set endpoint_url on it", want)
	}
	return prod.EndpointURL, want, nil
}

// settledProductFrom402 reads the merchant's product assertion (extra.productId) out of the 402
// and decides what settlement will record. A present assertion must match what the agent asked
// to buy — even at the token's own endpoint — or nothing is signed. An absent assertion means
// the merchant has not adopted the field and settlement falls back to the token's product;
// that is only a problem, and so only warned about, when a sibling was requested.
func settledProductFrom402(requirements x402types.PaymentRequirements, intended, tokenProduct string) (settled, warning string, err error) {
	raw, present := requirements.Extra["productId"]
	if present && raw != nil {
		s, ok := raw.(string)
		if !ok {
			return "", "", fmt.Errorf("merchant 402 extra.productId must be a hex string, got %T", raw)
		}
		if strings.TrimSpace(s) != "" {
			asserted, err := normalizeProductID("merchant 402 extra.productId", s)
			if err != nil {
				return "", "", err
			}
			if !strings.EqualFold(asserted, intended) {
				return "", "", fmt.Errorf("merchant's 402 names product %s but you asked to buy %s; refusing to sign — this endpoint is selling something else", asserted, intended)
			}
			return asserted, "", nil
		}
	}
	if !strings.EqualFold(intended, tokenProduct) {
		return tokenProduct, fmt.Sprintf("merchant did not assert extra.productId in its 402, so settlement attributed this purchase to the ref link's product %s, not %s; commission rate, escrow product and your proof-of-purchase follow the link's product", tokenProduct, intended), nil
	}
	return tokenProduct, "", nil
}
