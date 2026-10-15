package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// These tests stand a fake backend up rather than mocking the HTTP client, so the request
// that leaves the tool is a real one: real headers, real body, real status handling.
//
// What they CANNOT prove is that the real backend agrees — the path, the field names and
// the status for a given failure are all claims about a service that is not running here.
// merchant_live_test.go's REST tests are what check those, and they are the reason these
// are not the whole story.

type capturedRequest struct {
	method string
	path   string
	body   []byte
	header http.Header
}

// fakeBackend serves one canned reply and records what it was asked.
func fakeBackend(t *testing.T, status int, reply string, got *capturedRequest) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got.method = r.Method
		got.path = r.URL.Path
		got.body = body
		got.header = r.Header.Clone()

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// useFakeBackend installs a merchant key and points the tools at srv.
func useFakeBackend(t *testing.T, srv *httptest.Server, merchantID string) {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ks, err := parseKeystore(merchantID+":0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("REFERRER_API_URL", srv.URL)
}

// assertSignedFor checks that the captured request carries AgentAuth headers that recover
// to the expected address over the body the server actually received. This is the property
// the whole scheme rests on: the signature must cover the bytes that were SENT, not some
// earlier copy of them.
func assertSignedFor(t *testing.T, got capturedRequest, wantAddr string) {
	t.Helper()

	tsStr := got.header.Get("X-Agent-Timestamp")
	if tsStr == "" {
		t.Fatal("request carried no X-Agent-Timestamp")
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		t.Fatalf("X-Agent-Timestamp = %q: %v", tsStr, err)
	}

	sig := got.header.Get("X-Agent-Signature")
	if sig == "" {
		t.Fatal("request carried no X-Agent-Signature")
	}

	addr, err := recoverAgentAuth(got.body, ts, sig)
	if err != nil {
		t.Fatalf("recover from the sent request: %v", err)
	}
	if addr != wantAddr {
		t.Errorf("request recovered to %s, want %s", addr, wantAddr)
	}
}

func merchantKeyAddr(t *testing.T, merchantID string) string {
	t.Helper()
	key, err := signerKeys.KeyFor(merchantID)
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	return key.Address().Hex()
}

func TestSetMerchantProfile_RequestShape(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK,
		`{"merchant_id":4,"description":"stored copy","landing_page_url":"https://shop.example"}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{
		MerchantID:     "4",
		Description:    strPtr("sent copy"),
		LandingPageURL: strPtr("https://shop.example"),
	})
	if err != nil {
		t.Fatalf("set_merchant_profile: %v", err)
	}

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/v1/merchant/profile" {
		t.Errorf("path = %s, want /v1/merchant/profile", got.path)
	}
	assertSignedFor(t, got, merchantKeyAddr(t, "4"))

	// merchant_id must be a JSON NUMBER: the handler binds it as *int64 and a quoted string
	// fails the bind, which surfaces as a 400 "invalid merchant_id" that looks like a bad id.
	var sent map[string]any
	if err := json.Unmarshal(got.body, &sent); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	if _, ok := sent["merchant_id"].(float64); !ok {
		t.Errorf("merchant_id was sent as %T, want a JSON number", sent["merchant_id"])
	}

	// The reply's values win over the request's, so a normalisation by the backend is visible.
	if out.Description != "stored copy" {
		t.Errorf("description = %q, want the backend's stored value", out.Description)
	}
}

func strPtr(s string) *string { return &s }
func intPtr(v int) *int       { return &v }

func sentBody(t *testing.T, got capturedRequest) map[string]any {
	t.Helper()
	var sent map[string]any
	if err := json.Unmarshal(got.body, &sent); err != nil {
		t.Fatalf("request body is not JSON: %v", err)
	}
	return sent
}

// The endpoint is a partial update since REF-387: a field left out keeps its stored value, so the
// tool sends exactly the fields it was given — an omitted one must not arrive as "".
func TestSetMerchantProfile_SendsOnlyGivenFields(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"merchant_id":4,"description":"x","landing_page_url":"https://kept.example"}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{MerchantID: "4", Description: strPtr("x")})
	if err != nil {
		t.Fatalf("set_merchant_profile: %v", err)
	}
	sent := sentBody(t, got)
	for _, field := range []string{"landing_page_url", "default_commission_bps"} {
		if v, present := sent[field]; present {
			t.Errorf("%s was sent as %v though the caller did not set it; it would overwrite the stored value", field, v)
		}
	}
	if out.LandingPageURL != "https://kept.example" {
		t.Errorf("landing_page_url = %q, want the backend's stored value", out.LandingPageURL)
	}
}

// "" is a deliberate clear and must still be sent.
func TestSetMerchantProfile_EmptyStringIsSent(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"merchant_id":4,"description":"x","landing_page_url":""}`, &got)
	useFakeBackend(t, srv, "4")

	if _, _, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{MerchantID: "4", LandingPageURL: strPtr("")}); err != nil {
		t.Fatalf("set_merchant_profile: %v", err)
	}
	if v, present := sentBody(t, got)["landing_page_url"]; !present || v != "" {
		t.Errorf("landing_page_url = %v (present %v), want an explicit \"\"", v, present)
	}
}

func TestSetMerchantProfile_DefaultCommission(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"merchant_id":4,"description":"","landing_page_url":"","default_commission_bps":1250}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{MerchantID: "4", DefaultCommissionBps: intPtr(1250)})
	if err != nil {
		t.Fatalf("set_merchant_profile: %v", err)
	}
	if v, ok := sentBody(t, got)["default_commission_bps"].(float64); !ok || v != 1250 {
		t.Errorf("default_commission_bps sent as %v, want the number 1250", sentBody(t, got)["default_commission_bps"])
	}
	if out.DefaultCommissionBps == nil || *out.DefaultCommissionBps != 1250 {
		t.Errorf("output default_commission_bps = %v, want 1250 from the backend", out.DefaultCommissionBps)
	}
}

// Nothing to set: refuse before signing anything rather than send a request the backend rejects.
func TestSetMerchantProfile_RequiresAField(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{}`, &got)
	useFakeBackend(t, srv, "4")

	if _, _, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{MerchantID: "4"}); err == nil {
		t.Fatal("want an error when no field is given")
	}
	if got.method != "" {
		t.Errorf("a request was sent (%s %s) with nothing to update", got.method, got.path)
	}
}

func TestSetMerchantProfile_ConflictPointsAtActivation(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusConflict,
		`{"error":"merchant not registered — complete merchant registration before editing the profile"}`, &got)
	useFakeBackend(t, srv, "4")

	_, _, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{MerchantID: "4", Description: strPtr("x")})
	if err == nil {
		t.Fatal("want an error for a 409")
	}
	if !strings.Contains(err.Error(), "activate_merchant") {
		t.Errorf("a 409 does not point at activate_merchant: %v", err)
	}
	// The backend's own message is more specific than the status; it must survive.
	if !strings.Contains(err.Error(), "not registered") {
		t.Errorf("the backend's message was dropped: %v", err)
	}
}

// TestRESTError_UnauthorizedExplainsEveryCause is worth its own test because 401 has three
// unrelated causes on this scheme — wrong key, clock skew, resend — and a bare "401" sends
// an agent looking at the wrong one.
func TestRESTError_UnauthorizedExplainsEveryCause(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusUnauthorized, `{"error":"invalid signature"}`, &got)
	useFakeBackend(t, srv, "4")

	_, _, err := handleGetMerchantStats(t.Context(), nil, getMerchantStatsInput{MerchantID: "4"})
	if err == nil {
		t.Fatal("want an error for a 401")
	}
	msg := err.Error()
	for _, cause := range []string{"AGENT_KEYS", "clock", "signed afresh"} {
		if !strings.Contains(msg, cause) {
			t.Errorf("401 advice does not mention %q: %v", cause, err)
		}
	}
}

// The 404 case asserts BOTH causes. GET /v1/merchant/{id}/stats 404s when no identity
// exists on-chain AND when a merchant that does exist on-chain has no backend row — a live
// run against the real backend produced the second while the advice named only the first,
// which sends an agent to inspect a registry where its identity is sitting perfectly fine.
func TestRESTError_ForbiddenAndNotFoundAreDistinct(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "does not own"},
		{http.StatusNotFound, "no ERC-8004 identity"},
		{http.StatusNotFound, "no backend record"},
	} {
		var got capturedRequest
		srv := fakeBackend(t, tc.status, `{"error":"nope"}`, &got)
		useFakeBackend(t, srv, "4")

		_, _, err := handleGetMerchantStats(t.Context(), nil, getMerchantStatsInput{MerchantID: "4"})
		if err == nil {
			t.Fatalf("status %d: want an error", tc.status)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("status %d advice = %v, want it to mention %q", tc.status, err, tc.want)
		}
	}
}

func TestGetMerchantStats_RequestShapeAndExactIntegers(t *testing.T) {
	var got capturedRequest
	// revenue_gross is above 2^53, where a float64 decode rounds. USDC base units make that
	// reachable, and a rounded revenue figure is worse than a failed call.
	const bigRevenue = int64(9007199254740993)
	srv := fakeBackend(t, http.StatusOK,
		`{"conversions":3,"revenue_gross":9007199254740993,"escrow_holding":5,"escrow_settled":7,`+
			`"product_count":11,"active_product_count":9}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleGetMerchantStats(t.Context(), nil, getMerchantStatsInput{MerchantID: "4"})
	if err != nil {
		t.Fatalf("get_merchant_stats: %v", err)
	}

	if got.method != http.MethodGet {
		t.Errorf("method = %s, want GET", got.method)
	}
	if got.path != "/v1/merchant/4/stats" {
		t.Errorf("path = %s, want /v1/merchant/4/stats", got.path)
	}
	if len(got.body) != 0 {
		t.Errorf("GET sent a body of %d bytes", len(got.body))
	}
	// The empty-body signature path: the signed payload is the timestamp alone.
	assertSignedFor(t, got, merchantKeyAddr(t, "4"))

	if out.RevenueGross != bigRevenue {
		t.Errorf("revenue_gross = %d, want %d — the decode is lossy", out.RevenueGross, bigRevenue)
	}
	if out.Conversions != 3 || out.ProductCount != 11 || out.ActiveProductCount != 9 {
		t.Errorf("stats decoded wrong: %+v", out)
	}
	if out.MerchantID != "4" {
		t.Errorf("merchant_id = %q, want 4 (the response does not carry it)", out.MerchantID)
	}
}

// TestCheckProductReadiness_FailingProbeIsNotAnError pins the distinction the endpoint
// makes: a probe that ran and found the endpoint broken is a 200 with pass=false. Turning
// that into a tool error would tell the agent the check could not run.
func TestCheckProductReadiness_FailingProbeIsNotAnError(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK,
		`{"pass":false,"checks":[{"name":"status_402","ok":false,"detail":"got 200"},`+
			`{"name":"pay_to","ok":true}]}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{
		MerchantID: "4",
		Resource:   "https://shop.example/buy",
	})
	if err != nil {
		t.Fatalf("a failing probe was reported as an error: %v", err)
	}
	if out.Pass {
		t.Error("pass = true, want false")
	}
	if len(out.Checks) != 2 {
		t.Fatalf("got %d checks, want 2", len(out.Checks))
	}
	if out.Checks[0].Name != "status_402" || out.Checks[0].OK || out.Checks[0].Detail != "got 200" {
		t.Errorf("first check decoded wrong: %+v", out.Checks[0])
	}
	if !out.Checks[1].OK {
		t.Error("second check should be ok")
	}
	if out.Resource != "https://shop.example/buy" {
		t.Errorf("resource = %q, want it echoed", out.Resource)
	}

	if got.path != "/v1/merchant/product/readiness" {
		t.Errorf("path = %s", got.path)
	}
	var sent map[string]any
	if err := json.Unmarshal(got.body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if sent["resource"] != "https://shop.example/buy" {
		t.Errorf("resource was not sent: %v", sent)
	}
}

// TestCheckProductReadiness_V2 pins readiness v2 (REF-401): both URL names go out so an older
// backend still reads the referral URL, and the new fields come back decoded.
func TestCheckProductReadiness_V2(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"pass":true,"checks":[{"name":"returns_402","ok":true}],`+
		`"referral":{"checks":[],"price":"6000","asset":"0xusdc","network":"eip155:84532"},`+
		`"public":{"returns_402":true,"price":"5000","asset":"0xusdc","network":"eip155:84532","pay_to":"0xmerchant"},`+
		`"price_comparison":{"referral":"6000","public":"5000","referral_costs_more":true},`+
		`"controls_endpoint":{"ok":false,"detail":"referral host a differs from public host b"}}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{
		MerchantID:  "4",
		ReferralURL: "https://a.example/ref",
		PublicURL:   "https://b.example/pub",
	})
	if err != nil {
		t.Fatalf("check_product_readiness: %v", err)
	}
	var sent map[string]any
	if err := json.Unmarshal(got.body, &sent); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if sent["referral_url"] != "https://a.example/ref" || sent["resource"] != "https://a.example/ref" || sent["public_url"] != "https://b.example/pub" {
		t.Errorf("sent %v", sent)
	}
	if out.Referral.Price != "6000" || out.Referral.Network != "eip155:84532" {
		t.Errorf("referral = %+v", out.Referral)
	}
	if out.Public == nil || out.Public.Price != "5000" || out.Public.PayTo != "0xmerchant" {
		t.Errorf("public = %+v", out.Public)
	}
	if out.PriceComparison == nil || !out.PriceComparison.ReferralCostsMore {
		t.Errorf("price_comparison = %+v", out.PriceComparison)
	}
	if out.ControlsEndpoint == nil || out.ControlsEndpoint.OK == nil || *out.ControlsEndpoint.OK {
		t.Errorf("controls_endpoint = %+v", out.ControlsEndpoint)
	}
	if out.ReferralURL != "https://a.example/ref" || out.Resource != "https://a.example/ref" || out.PublicURL != "https://b.example/pub" {
		t.Errorf("echo = %q %q %q", out.ReferralURL, out.Resource, out.PublicURL)
	}
}

// Without a public URL none is sent, and a pre-v2 answer (pass and checks only) still decodes.
func TestCheckProductReadiness_ResourceAliasAndOldAnswer(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"pass":true,"checks":[{"name":"returns_402","ok":true}]}`, &got)
	useFakeBackend(t, srv, "4")

	_, out, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{MerchantID: "4", Resource: "https://a.example/ref"})
	if err != nil {
		t.Fatalf("check_product_readiness: %v", err)
	}
	var sent map[string]any
	_ = json.Unmarshal(got.body, &sent)
	if _, ok := sent["public_url"]; ok {
		t.Errorf("public_url sent without one given: %v", sent)
	}
	if sent["referral_url"] != "https://a.example/ref" {
		t.Errorf("the resource alias did not become referral_url: %v", sent)
	}
	if !out.Pass || out.Public != nil || out.PriceComparison != nil || out.ControlsEndpoint != nil {
		t.Errorf("old answer decoded as %+v", out)
	}
}

func TestCheckProductReadiness_ConflictingNamesRefused(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"pass":true}`, &got)
	useFakeBackend(t, srv, "4")
	_, _, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{MerchantID: "4", ReferralURL: "https://a.example/1", Resource: "https://a.example/2"})
	if err == nil || got.path != "" {
		t.Fatalf("err = %v, sent %q; want a refusal before sending", err, got.path)
	}
}

func TestCheckProductReadiness_ResourceRequired(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `{"pass":true}`, &got)
	useFakeBackend(t, srv, "4")

	_, _, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{MerchantID: "4"})
	if err == nil {
		t.Fatal("an empty resource was accepted")
	}
	if got.path != "" {
		t.Errorf("a request was sent despite the missing resource: %s", got.path)
	}
}

func TestAPIBaseURL_MissingIsNamed(t *testing.T) {
	t.Setenv("REFERRER_API_URL", "")
	if _, err := apiBaseURL(); err == nil || !strings.Contains(err.Error(), "REFERRER_API_URL") {
		t.Fatalf("want an error naming the variable, got %v", err)
	}
}

// TestAPIBaseURL_TrailingSlash keeps the joined path from doubling its separator; some
// routers treat //v1/... as a different, unmatched route.
func TestAPIBaseURL_TrailingSlash(t *testing.T) {
	t.Setenv("REFERRER_API_URL", "http://localhost:8080/")
	base, err := apiBaseURL()
	if err != nil {
		t.Fatalf("apiBaseURL: %v", err)
	}
	if base != "http://localhost:8080" {
		t.Errorf("base = %q, want the trailing slash trimmed", base)
	}
}

func TestMerchantIDForREST_RejectsOversize(t *testing.T) {
	tooBig := new(big.Int).Lsh(big.NewInt(1), 64)
	if _, err := merchantIDForREST(tooBig); err == nil {
		t.Fatal("an id beyond int64 was accepted; the backend's JSON cannot carry it")
	}

	// Zero is valid — the first identity on a registry (see parseMerchantID).
	if got, err := merchantIDForREST(big.NewInt(0)); err != nil || got != 0 {
		t.Errorf("merchantIDForREST(0) = %d, %v", got, err)
	}
}

func TestCallAuthedJSON_NonObjectBodyIsReported(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `<html>gateway</html>`, &got)
	useFakeBackend(t, srv, "4")

	// set_merchant_profile reads its reply through callAuthedJSON.
	_, _, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{
		MerchantID:  "4",
		Description: strPtr("d"),
	})
	if err == nil {
		t.Fatal("a non-JSON 200 was accepted")
	}
	if !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("error does not explain the body: %v", err)
	}
}

// check_product_readiness decodes into a typed reply (callAuthedInto); a gateway page must
// still be reported with the body, not as a failed probe.
func TestCheckProductReadiness_NonJSONBodyIsReported(t *testing.T) {
	var got capturedRequest
	srv := fakeBackend(t, http.StatusOK, `<html>gateway</html>`, &got)
	useFakeBackend(t, srv, "4")

	_, _, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{MerchantID: "4", ReferralURL: "https://shop.example/buy"})
	if err == nil || !strings.Contains(err.Error(), "<html>gateway</html>") {
		t.Fatalf("err = %v, want the body named", err)
	}
}
