package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	x402types "github.com/x402-foundation/x402/go/types"

	"github.com/OpenSoukAI/agent-mcp/internal/endpointpath"
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

// settledProductFrom402 decides what settlement will record, from the merchant's 402 (REF-562).
// The facilitator settles on the product registered at the path in extra.endpoint, so that path
// must be the one the signer called, or nothing is signed. The retired extra.productId is refused:
// the facilitator rejects it. An absent endpoint means the merchant has not adopted the field and
// settlement falls back to the token's product, which is only warned about for a sibling.
func settledProductFrom402(requirements x402types.PaymentRequirements, calledURL, intended, tokenProduct string) (settled, warning string, err error) {
	if raw, ok := requirements.Extra["productId"]; ok && raw != nil && raw != "" {
		return "", "", fmt.Errorf("merchant's 402 sends extra.productId, which the protocol no longer accepts (it names the endpoint in extra.endpoint instead); refusing to sign a payment the facilitator would reject")
	}
	raw, present := requirements.Extra["endpoint"]
	if present && raw != nil && raw != "" {
		s, ok := raw.(string)
		if !ok {
			return "", "", fmt.Errorf("merchant 402 extra.endpoint must be a URL or path string, got %T", raw)
		}
		reported, err := endpointpath.Normalize(s)
		if err != nil {
			return "", "", fmt.Errorf("merchant 402 extra.endpoint %q is not a valid endpoint: %v", s, err)
		}
		called, err := endpointpath.Normalize(calledURL)
		if err != nil {
			return "", "", fmt.Errorf("called URL %q is not a valid endpoint: %v", calledURL, err)
		}
		if reported != called {
			return "", "", fmt.Errorf("merchant's 402 reports endpoint %s but you called %s; refusing to sign — settlement would record the product registered at %s", reported, called, reported)
		}
		return intended, "", nil
	}
	if !strings.EqualFold(intended, tokenProduct) {
		return tokenProduct, fmt.Sprintf("merchant's 402 reports no extra.endpoint, so settlement attributes this purchase to the ref link's product %s, not %s; commission rate, escrow product and your proof-of-purchase follow the link's product", tokenProduct, intended), nil
	}
	return tokenProduct, "", nil
}

// concretePayURL is the URL to pay for a product registered at registered (REF-562). A fixed
// endpoint is paid as registered, or at a given url with the same path. A template such as
// /letters/{id} can only be paid at a concrete url the agent gives: same scheme, host and port,
// and a path the template matches under the facilitator's rule.
func concretePayURL(registered, given string) (payURL string, templated bool, err error) {
	regPath, err := endpointpath.Normalize(registered)
	if err != nil {
		return "", false, fmt.Errorf("the product's endpoint %s is not a valid endpoint: %v", registered, err)
	}
	templated = endpointpath.IsTemplate(regPath)
	if strings.TrimSpace(given) == "" {
		if templated {
			return "", false, fmt.Errorf("this product's endpoint %s is a template; pass url= with the concrete URL to pay", registered)
		}
		return registered, false, nil
	}
	g, err := url.Parse(strings.TrimSpace(given))
	if err != nil || (g.Scheme != "http" && g.Scheme != "https") || g.Host == "" {
		return "", false, fmt.Errorf("url %s must be an absolute http(s) URL", given)
	}
	if g.User != nil {
		return "", false, fmt.Errorf("url %s must not carry a username or password", given)
	}
	r, err := url.Parse(strings.TrimSpace(registered))
	if err != nil || hostKey(r) != hostKey(g) {
		return "", false, fmt.Errorf("url %s is not on the product's host %s", given, registered)
	}
	givenPath, err := endpointpath.Normalize(given)
	if err != nil {
		return "", false, fmt.Errorf("url %s is not a valid endpoint: %v", given, err)
	}
	if !endpointpath.Matches(regPath, givenPath) {
		return "", false, fmt.Errorf("url path %s does not fit the product's endpoint %s", givenPath, regPath)
	}
	return strings.TrimSpace(given), templated, nil
}

// hostKey is scheme, lowercased host and port, with the scheme's default port made explicit.
func hostKey(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[strings.ToLower(u.Scheme)]
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Hostname()) + ":" + port
}

// resolvesToIntended refuses unless the facilitator's path rule, run over the merchant's listed
// products, resolves payURL to the intended product (REF-562). A fixed path beats a template, so
// a url fitting the intended template can still settle as another product registered at exactly
// that path. The catalog comes from the pinned API origin; if it cannot be read, nothing is signed.
func resolvesToIntended(ctx context.Context, client *http.Client, apiBase, merchantID, intended, payURL string) error {
	requested, err := endpointpath.Normalize(payURL)
	if err != nil {
		return fmt.Errorf("url %s is not a valid endpoint: %v", payURL, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(apiBase, "/")+"/v1/merchant/"+url.PathEscape(merchantID)+"/catalog", nil)
	if err != nil {
		return fmt.Errorf("build catalog lookup: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot verify which product url %s settles as: catalog lookup: %w", payURL, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("cannot verify which product url %s settles as: merchant %s catalog answered HTTP %d", payURL, merchantID, resp.StatusCode)
	}
	var cat struct {
		Products []struct {
			ProductID   string `json:"product_id"`
			EndpointURL string `json:"endpoint_url"`
		} `json:"products"`
	}
	if err := json.Unmarshal(body, &cat); err != nil {
		return fmt.Errorf("cannot verify which product url %s settles as: parse catalog: %w", payURL, err)
	}
	var paths, ids []string
	for _, p := range cat.Products {
		path, err := endpointpath.Normalize(p.EndpointURL)
		if err != nil {
			continue
		}
		paths = append(paths, path)
		ids = append(ids, p.ProductID)
	}
	i, err := endpointpath.Resolve(paths, requested)
	switch {
	case errors.Is(err, endpointpath.ErrNoMatch):
		return fmt.Errorf("url %s matches no listed product of merchant %s", payURL, merchantID)
	case errors.Is(err, endpointpath.ErrAmbiguous):
		return fmt.Errorf("url %s matches several listed products of merchant %s; the facilitator would refuse it", payURL, merchantID)
	case err != nil:
		return fmt.Errorf("url %s: %v", payURL, err)
	}
	if !strings.EqualFold(ids[i], intended) {
		return fmt.Errorf("url %s settles as product %s, not %s: another product is registered at that exact path", payURL, ids[i], intended)
	}
	return nil
}
