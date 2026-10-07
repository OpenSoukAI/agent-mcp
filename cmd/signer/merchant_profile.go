package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── set_merchant_profile ────────────────────────────────────────────────────────

// Pointers so an omitted field stays distinct from "": the endpoint is a partial update
// (backend REF-387), and only the fields given are sent.
type setMerchantProfileInput struct {
	MerchantID           string  `json:"merchant_id"`                      // decimal; the merchant's own ERC-8004 id
	Description          *string `json:"description,omitempty"`            // public profile copy; "" clears it
	LandingPageURL       *string `json:"landing_page_url,omitempty"`       // public http(s) link; "" clears it
	DefaultCommissionBps *int    `json:"default_commission_bps,omitempty"` // 0..10000; prefills new products
}

type setMerchantProfileOutput struct {
	MerchantID           string `json:"merchant_id"`
	Description          string `json:"description"`
	LandingPageURL       string `json:"landing_page_url"`
	DefaultCommissionBps *int   `json:"default_commission_bps"`
}

func handleSetMerchantProfile(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in setMerchantProfileInput,
) (*sdkmcp.CallToolResult, setMerchantProfileOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, setMerchantProfileOutput{}, err
	}
	restID, err := merchantIDForREST(merchantID)
	if err != nil {
		return nil, setMerchantProfileOutput{}, err
	}

	req := map[string]any{"merchant_id": restID}
	if in.Description != nil {
		req["description"] = *in.Description
	}
	if in.LandingPageURL != nil {
		req["landing_page_url"] = *in.LandingPageURL
	}
	if in.DefaultCommissionBps != nil {
		req["default_commission_bps"] = *in.DefaultCommissionBps
	}
	if len(req) == 1 {
		return nil, setMerchantProfileOutput{}, fmt.Errorf("nothing to update: pass description, landing_page_url or default_commission_bps")
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, setMerchantProfileOutput{}, fmt.Errorf("encode request: %w", err)
	}

	resp, err := callAuthedJSON(ctx, "set_merchant_profile", http.MethodPost, "/v1/merchant/profile",
		body, merchantID, map[int]string{
			http.StatusConflict:   "this merchant has no backend record yet — call activate_merchant first, then set the profile",
			http.StatusBadRequest: "the backend rejected a field; the message above names which one",
		})
	if err != nil {
		return nil, setMerchantProfileOutput{}, err
	}

	// Echo what the backend stored rather than what was sent, so a value it normalised is
	// visible to the caller.
	out := setMerchantProfileOutput{
		MerchantID:     merchantID.String(),
		Description:    stringField(resp, "description"),
		LandingPageURL: stringField(resp, "landing_page_url"),
	}
	if v, ok := resp["default_commission_bps"].(float64); ok {
		bps := int(v)
		out.DefaultCommissionBps = &bps
	}
	return nil, out, nil
}

// ── check_product_readiness ─────────────────────────────────────────────────────

type checkProductReadinessInput struct {
	// MerchantID selects the signing key ONLY. The endpoint is authenticated but not
	// owner-scoped — it probes whatever URL it is given — so this is not a claim about who
	// owns the resource.
	MerchantID  string `json:"merchant_id"`
	ReferralURL string `json:"referral_url,omitempty"` // the product's referral x402 endpoint
	Resource    string `json:"resource,omitempty"`     // the original name of referral_url
	PublicURL   string `json:"public_url,omitempty"`   // the merchant's public endpoint, optional
}

type readinessCheckResult struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// readinessRoute is what the referral probe found. Price is in the asset's base units.
type readinessRoute struct {
	Price   string `json:"price,omitempty"`
	Asset   string `json:"asset,omitempty"`
	Network string `json:"network,omitempty"`
}

// readinessPublic is the public endpoint's own probe. It never affects pass.
type readinessPublic struct {
	Returns402 bool   `json:"returns_402"`
	Price      string `json:"price,omitempty"`
	Asset      string `json:"asset,omitempty"`
	Network    string `json:"network,omitempty"`
	PayTo      string `json:"pay_to,omitempty"`
	Detail     string `json:"detail,omitempty"`
}

// readinessComparison is present only when both routes are priced in the same asset on the
// same network.
type readinessComparison struct {
	Referral          string `json:"referral"`
	Public            string `json:"public"`
	ReferralCostsMore bool   `json:"referral_costs_more"`
}

// readinessControl is the advisory host check: ok is null when no public URL was given.
type readinessControl struct {
	OK     *bool  `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type checkProductReadinessOutput struct {
	Pass            bool                   `json:"pass"`
	Checks          []readinessCheckResult `json:"checks"`
	ReferralURL     string                 `json:"referral_url"`
	Resource        string                 `json:"resource"` // referral_url under its original name
	PublicURL       string                 `json:"public_url,omitempty"`
	Referral        readinessRoute         `json:"referral"`
	Public          *readinessPublic       `json:"public,omitempty"`
	PriceComparison *readinessComparison   `json:"price_comparison,omitempty"`
	// ControlsEndpoint is absent from a backend older than readiness v2 (REF-401).
	ControlsEndpoint *readinessControl `json:"controls_endpoint,omitempty"`
}

func handleCheckProductReadiness(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in checkProductReadinessInput,
) (*sdkmcp.CallToolResult, checkProductReadinessOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, checkProductReadinessOutput{}, err
	}
	referral := in.ReferralURL
	if referral == "" {
		referral = in.Resource
	} else if in.Resource != "" && in.Resource != referral {
		return nil, checkProductReadinessOutput{}, fmt.Errorf("referral_url and resource name the same field and differ; pass referral_url only")
	}
	if referral == "" {
		return nil, checkProductReadinessOutput{}, fmt.Errorf("referral_url is required (the product's referral x402 endpoint URL)")
	}

	// Both names are sent: a backend from before readiness v2 reads resource and ignores the
	// rest, and a current one prefers referral_url.
	req := map[string]any{"referral_url": referral, "resource": referral}
	if in.PublicURL != "" {
		req["public_url"] = in.PublicURL
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, checkProductReadinessOutput{}, fmt.Errorf("encode request: %w", err)
	}

	// A probe that ran and found the endpoint misconfigured is a 200 with pass=false, so a
	// failing check is data here, not an error. Only the probe failing to run is an error.
	var out checkProductReadinessOutput
	if err := callAuthedInto(ctx, "check_product_readiness", http.MethodPost,
		"/v1/merchant/product/readiness", body, merchantID, map[int]string{
			http.StatusBadRequest: "referral_url and public_url must be absolute http(s) URLs",
		}, &out); err != nil {
		return nil, checkProductReadinessOutput{}, err
	}
	out.ReferralURL, out.Resource = referral, referral
	out.PublicURL = in.PublicURL
	return nil, out, nil
}

// ── get_merchant_stats ──────────────────────────────────────────────────────────

type getMerchantStatsInput struct {
	MerchantID string `json:"merchant_id"`
}

type getMerchantStatsOutput struct {
	MerchantID         string `json:"merchant_id"`
	Conversions        int64  `json:"conversions"`
	RevenueGross       int64  `json:"revenue_gross"`
	EscrowHolding      int64  `json:"escrow_holding"`
	EscrowSettled      int64  `json:"escrow_settled"`
	ProductCount       int64  `json:"product_count"`
	ActiveProductCount int64  `json:"active_product_count"`
}

func handleGetMerchantStats(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in getMerchantStatsInput,
) (*sdkmcp.CallToolResult, getMerchantStatsOutput, error) {
	merchantID, err := parseMerchantID(in.MerchantID)
	if err != nil {
		return nil, getMerchantStatsOutput{}, err
	}
	restID, err := merchantIDForREST(merchantID)
	if err != nil {
		return nil, getMerchantStatsOutput{}, err
	}

	// A GET with no body: the signed payload is the timestamp alone (see agentauth.go).
	// Decoded into the typed output directly, so the int64 counts stay exact.
	out := getMerchantStatsOutput{MerchantID: merchantID.String()}
	if err := callAuthedInto(ctx, "get_merchant_stats", http.MethodGet,
		fmt.Sprintf("/v1/merchant/%d/stats", restID), nil, merchantID, map[int]string{
			// This route 404s for TWO unrelated reasons: no such identity on-chain, and no
			// backend row for a merchant that does exist on-chain. The generic advice blamed
			// the chain, which sends an agent looking at a registry where the identity is
			// sitting perfectly fine.
			http.StatusNotFound: "either no ERC-8004 identity exists for this merchant_id on this chain, or the merchant has no backend record yet — call activate_merchant if the identity is minted",
		}, &out); err != nil {
		return nil, getMerchantStatsOutput{}, err
	}

	// The response carries no merchant_id, so restore it after the decode.
	out.MerchantID = merchantID.String()
	return nil, out, nil
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}
