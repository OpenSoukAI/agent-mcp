package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/crypto"
)

// ── Live merchant-write tests ───────────────────────────────────────────────────
//
// These run the real tool handlers against a real chain. Nothing else can: the unit tests
// prove the inputs are parsed and the revert advice is reachable, but only a node proves
// the ABI literals describe the deployed contracts and that the arguments arrive in the
// order the contract reads them. An argument-order mistake packs and sends perfectly.
//
// Skipped when MERCHANT_LIVE_RPC is unset, so the default `go test ./...` needs no chain.
// Set it and every other variable below must be present and correct, or the test FAILS
// rather than skipping — a half-configured live run that silently passes is worse than no
// live run, because it looks like coverage.
//
// Preconditions on the chain (see the REF-251 notes in the PR):
//   - MERCHANT_LIVE_MERCHANT_ID is a minted ERC-8004 identity owned by OWNER_KEY's address
//   - MERCHANT_LIVE_PRODUCT_ID already exists for it
//   - OTHER_KEY's address owns neither

type liveEnv struct {
	rpc              string
	chainID          string
	merchantRegistry string
	productRegistry  string
	merchantID       string
	ownerKeyHex      string
	otherKeyHex      string
	productID        string
}

func liveMerchantEnv(t *testing.T) liveEnv {
	t.Helper()

	rpc := os.Getenv("MERCHANT_LIVE_RPC")
	if rpc == "" {
		t.Skip("MERCHANT_LIVE_RPC not set; skipping the live merchant writes. Set it together " +
			"with MERCHANT_LIVE_CHAIN_ID, MERCHANT_LIVE_MERCHANT_REGISTRY, " +
			"MERCHANT_LIVE_PRODUCT_REGISTRY, MERCHANT_LIVE_MERCHANT_ID, " +
			"MERCHANT_LIVE_PRODUCT_ID, MERCHANT_LIVE_OWNER_KEY and MERCHANT_LIVE_OTHER_KEY.")
	}

	e := liveEnv{
		rpc:              rpc,
		chainID:          os.Getenv("MERCHANT_LIVE_CHAIN_ID"),
		merchantRegistry: os.Getenv("MERCHANT_LIVE_MERCHANT_REGISTRY"),
		productRegistry:  os.Getenv("MERCHANT_LIVE_PRODUCT_REGISTRY"),
		merchantID:       os.Getenv("MERCHANT_LIVE_MERCHANT_ID"),
		ownerKeyHex:      os.Getenv("MERCHANT_LIVE_OWNER_KEY"),
		otherKeyHex:      os.Getenv("MERCHANT_LIVE_OTHER_KEY"),
		productID:        os.Getenv("MERCHANT_LIVE_PRODUCT_ID"),
	}

	for name, v := range map[string]string{
		"MERCHANT_LIVE_CHAIN_ID":          e.chainID,
		"MERCHANT_LIVE_MERCHANT_REGISTRY": e.merchantRegistry,
		"MERCHANT_LIVE_PRODUCT_REGISTRY":  e.productRegistry,
		"MERCHANT_LIVE_MERCHANT_ID":       e.merchantID,
		"MERCHANT_LIVE_PRODUCT_ID":        e.productID,
		"MERCHANT_LIVE_OWNER_KEY":         e.ownerKeyHex,
		"MERCHANT_LIVE_OTHER_KEY":         e.otherKeyHex,
	} {
		if v == "" {
			t.Fatalf("MERCHANT_LIVE_RPC is set but %s is empty — configure the whole live "+
				"environment or none of it", name)
		}
	}
	return e
}

// use points the handlers at this chain and installs keyHex as the merchant's signing key.
func (e liveEnv) use(t *testing.T, keyHex string) {
	t.Helper()

	key, err := crypto.HexToECDSA(strings.TrimPrefix(keyHex, "0x"))
	if err != nil {
		t.Fatalf("parse live key: %v", err)
	}
	ks, err := parseKeystore(e.merchantID+":0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("BASE_RPC_URL", e.rpc)
	t.Setenv("CHAIN_ID", e.chainID)
	t.Setenv("MERCHANT_REGISTRY_ADDRESS", e.merchantRegistry)
	t.Setenv("PRODUCT_REGISTRY_ADDRESS", e.productRegistry)
}

// readProduct calls getProduct and returns the fields the tools change.
func (e liveEnv) readProduct(t *testing.T) (commissionBps uint16, active bool, productType uint8) {
	t.Helper()

	client, _, err := dialChain(context.Background(), e.chainID)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	productID, err := parseProductID(e.productID)
	if err != nil {
		t.Fatalf("parse product id: %v", err)
	}
	merchantID, err := parseMerchantID(e.merchantID)
	if err != nil {
		t.Fatalf("parse merchant id: %v", err)
	}

	addr, err := requireAddr("PRODUCT_REGISTRY_ADDRESS")
	if err != nil {
		t.Fatalf("product registry address: %v", err)
	}

	var out []any
	contract := bind.NewBoundContract(addr, productRegistryABI, client, client, client)
	if err := contract.Call(&bind.CallOpts{Context: context.Background()}, &out,
		"getProduct", merchantID, productID); err != nil {
		t.Fatalf("getProduct: %v", err)
	}

	p, ok := out[0].(struct {
		MerchantId     *big.Int `json:"merchantId"`
		ProductId      [32]byte `json:"productId"`
		CommissionBps  uint16   `json:"commissionBps"`
		Active         bool     `json:"active"`
		ProductCardURI string   `json:"productCardURI"`
		CreatedAt      *big.Int `json:"createdAt"`
		ProductType    uint8    `json:"productType"`
	})
	if !ok {
		t.Fatalf("getProduct returned %T", out[0])
	}
	return p.CommissionBps, p.Active, p.ProductType
}

// TestLive_SetMerchantActive exercises the MerchantRegistry.setActive write through the
// shared merchantWrite path. activate_merchant wraps this call, so proving it here means
// that tool only has to be tested for its orchestration.
func TestLive_SetMerchantActive(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.ownerKeyHex)

	merchantID, err := parseMerchantID(e.merchantID)
	if err != nil {
		t.Fatalf("parse merchant id: %v", err)
	}

	w := merchantWrite{
		tool:    "activate_merchant",
		addrEnv: "MERCHANT_REGISTRY_ADDRESS",
		abi:     merchantRegistryABI,
		method:  "setActive",
		reverts: newRevertTable(map[string]string{}),
		advice:  "does the signer key own merchant_id?",
	}

	txHash, from, err := w.send(t.Context(), merchantID, e.chainID, merchantID, true)
	if err != nil {
		t.Fatalf("setActive: %v", err)
	}
	if !strings.HasPrefix(txHash, "0x") {
		t.Errorf("tx_hash = %q", txHash)
	}
	if from == "" {
		t.Error("no sending address reported")
	}

	if !e.readMerchantActive(t) {
		t.Fatal("setActive(true) was mined but isActive is still false — the write landed " +
			"somewhere other than this merchant's flag")
	}
}

func (e liveEnv) readMerchantActive(t *testing.T) bool {
	t.Helper()

	client, _, err := dialChain(context.Background(), e.chainID)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	merchantID, err := parseMerchantID(e.merchantID)
	if err != nil {
		t.Fatalf("parse merchant id: %v", err)
	}
	addr, err := requireAddr("MERCHANT_REGISTRY_ADDRESS")
	if err != nil {
		t.Fatalf("merchant registry address: %v", err)
	}

	var out []any
	contract := bind.NewBoundContract(addr, merchantRegistryABI, client, client, client)
	if err := contract.Call(&bind.CallOpts{Context: context.Background()}, &out, "isActive", merchantID); err != nil {
		t.Fatalf("isActive: %v", err)
	}
	active, ok := out[0].(bool)
	if !ok {
		t.Fatalf("isActive returned %T", out[0])
	}
	return active
}

// TestLive_SetProductCommission is the argument-order check. A call that passed
// (merchantId, commissionBps, productId) packs, sends and mines; only reading the value
// back off the product shows it went to the wrong field.
func TestLive_SetProductCommission(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.ownerKeyHex)

	before, _, _ := e.readProduct(t)

	// A rate that differs from whatever is stored, so the read-back cannot pass by accident.
	want := 1234
	if int(before) == want {
		want = 4321
	}

	_, out, err := handleSetProductCommission(t.Context(), nil, setProductCommissionInput{
		MerchantID:    e.merchantID,
		ProductID:     e.productID,
		CommissionBps: want,
		ChainID:       e.chainID,
	})
	if err != nil {
		t.Fatalf("set_product_commission: %v", err)
	}
	if out.CommissionBps != want {
		t.Errorf("reported commission_bps = %d, want %d", out.CommissionBps, want)
	}

	got, _, _ := e.readProduct(t)
	if int(got) != want {
		t.Fatalf("on-chain commissionBps = %d, want %d (was %d) — the transaction succeeded "+
			"but the rate did not change, so the arguments reached the wrong parameters",
			got, want, before)
	}
}

func TestLive_SetProductActive(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.ownerKeyHex)

	for _, want := range []bool{false, true} {
		active := want
		if _, _, err := handleSetProductActive(t.Context(), nil, setProductActiveInput{
			MerchantID: e.merchantID,
			ProductID:  e.productID,
			Active:     &active,
			ChainID:    e.chainID,
		}); err != nil {
			t.Fatalf("set_product_active(%v): %v", want, err)
		}

		if _, got, _ := e.readProduct(t); got != want {
			t.Fatalf("on-chain active = %v, want %v", got, want)
		}
	}
}

// TestLive_ProductNotFoundIsFriendly provokes the revert rather than asserting the table in
// isolation: it proves the selector the node actually returns is the one the table holds.
func TestLive_ProductNotFoundIsFriendly(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.ownerKeyHex)

	_, _, err := handleSetProductCommission(t.Context(), nil, setProductCommissionInput{
		MerchantID:    e.merchantID,
		ProductID:     "0x" + strings.Repeat("cd", 32), // never added
		CommissionBps: 500,
		ChainID:       e.chainID,
	})
	if err == nil {
		t.Fatal("setting the commission on a nonexistent product succeeded")
	}
	if !strings.Contains(err.Error(), "add_product") {
		t.Errorf("ProductNotFound did not decode to its advice: %v", err)
	}
}

// TestLive_UnauthorisedIsFriendly does the same for the role check, with a key that owns
// nothing. Unauthorised is the revert an agent is most likely to hit and least able to
// diagnose from a selector.
func TestLive_UnauthorisedIsFriendly(t *testing.T) {
	e := liveMerchantEnv(t)
	e.use(t, e.otherKeyHex)

	_, _, err := handleSetProductCommission(t.Context(), nil, setProductCommissionInput{
		MerchantID:    e.merchantID,
		ProductID:     e.productID,
		CommissionBps: 500,
		ChainID:       e.chainID,
	})
	if err == nil {
		t.Fatal("a key that owns neither the merchant nor the role changed the commission")
	}
	if !strings.Contains(err.Error(), "COMMISSION_MANAGER") {
		t.Errorf("Unauthorised did not decode to its advice: %v", err)
	}
}

// ── Live REST tests ─────────────────────────────────────────────────────────────
//
// Gated separately on MERCHANT_LIVE_API, because a chain can be up without the backend.
//
// These are deliberately thin. The signature scheme itself is pinned by the golden vector
// in agentauth_test.go, and the backend's own middleware tests already cover unsigned,
// stale, replayed and tampered requests far better than a round trip from here could.
// What only a live backend can prove is the part merchant_rest_test.go's fake cannot: that
// the path exists, that the field names are the ones the handler binds, and that a success
// really is a 200 with the body these tools decode.

// liveAPI returns the backend base URL, or skips.
func liveAPI(t *testing.T) string {
	t.Helper()

	api := os.Getenv("MERCHANT_LIVE_API")
	if api == "" {
		t.Skip("MERCHANT_LIVE_API not set; skipping the live backend calls. Set it to the " +
			"backend base URL (e.g. http://localhost:8080) alongside the MERCHANT_LIVE_* " +
			"chain variables.")
	}
	return strings.TrimSuffix(api, "/")
}

// useAPI installs the merchant's key and points the REST tools at the live backend.
func (e liveEnv) useAPI(t *testing.T, api string) {
	t.Helper()

	e.use(t, e.ownerKeyHex)
	t.Setenv("REFERRER_API_URL", api)
}

func TestLive_GetMerchantStats(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.useAPI(t, api)

	_, out, err := handleGetMerchantStats(t.Context(), nil, getMerchantStatsInput{
		MerchantID: e.merchantID,
	})
	if err != nil {
		t.Fatalf("get_merchant_stats: %v", err)
	}

	if out.MerchantID != e.merchantID {
		t.Errorf("merchant_id = %q, want %q", out.MerchantID, e.merchantID)
	}

	// The figures depend on the fixture, so their VALUES are not assertable — which means
	// value assertions alone cannot tell a decoded stats body from an empty object: every
	// field would be zero and "active <= total" would hold. So check the keys are actually
	// present in the response. Found by mutation: pointing the tool at a path that returns a
	// different 200 object passed every value check.
	merchantID, err := parseMerchantID(e.merchantID)
	if err != nil {
		t.Fatalf("parse merchant id: %v", err)
	}
	rawBody, err := callAuthedRaw(t.Context(), "live_stats", http.MethodGet,
		"/v1/merchant/"+e.merchantID+"/stats", nil, merchantID, nil)
	if err != nil {
		t.Fatalf("raw stats read: %v", err)
	}

	// json.Number, not map[string]any: a generic decode turns every number into a float64
	// and rounds anything above 2^53, which would make this comparison disagree with a
	// correct tool on a large revenue figure. (It did, before this.)
	dec := json.NewDecoder(bytes.NewReader(rawBody))
	dec.UseNumber()
	var raw map[string]json.Number
	if err := dec.Decode(&raw); err != nil {
		t.Fatalf("decode raw stats: %v", err)
	}
	// Compare the tool's output to that raw read field by field. Presence alone is not
	// enough: the raw read uses its own path, so it cannot see where the TOOL went. Equality
	// can — a tool pointed at a different endpoint reports zeros while the raw read does not.
	for key, want := range map[string]int64{
		"conversions":          out.Conversions,
		"revenue_gross":        out.RevenueGross,
		"escrow_holding":       out.EscrowHolding,
		"escrow_settled":       out.EscrowSettled,
		"product_count":        out.ProductCount,
		"active_product_count": out.ActiveProductCount,
	} {
		v, present := raw[key]
		if !present {
			t.Errorf("the stats response has no %q field — this is not the stats endpoint's "+
				"body, or its field names have changed", key)
			continue
		}
		got, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			t.Errorf("%q came back as %q, want an integer", key, v)
			continue
		}
		if got != want {
			t.Errorf("%s: the tool reported %d but the stats endpoint says %d — the tool is not "+
				"reading this endpoint", key, want, got)
		}
	}

	// The active subset can never exceed the total; a decode that crossed the two fields
	// would routinely break this.
	if out.ActiveProductCount > out.ProductCount {
		t.Errorf("active_product_count %d exceeds product_count %d — the fields are crossed",
			out.ActiveProductCount, out.ProductCount)
	}
	if out.Conversions < 0 || out.RevenueGross < 0 {
		t.Errorf("negative figures: %+v", out)
	}
}

// TestLive_StatsRequiresSignature guards against the tools being pointed at an endpoint
// that never checked the signature. Every other live test would pass just as happily
// against an open route, which would mean shipping a merchant's revenue unauthenticated.
func TestLive_StatsRequiresSignature(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)

	url := api + "/v1/merchant/" + e.merchantID + "/stats"
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}

	resp, err := (&http.Client{Timeout: restTimeout}).Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned GET %s returned %d, want 401 — this route is not authenticated, so "+
			"the merchant's revenue is readable by anyone", url, resp.StatusCode)
	}
}

// TestLive_SetMerchantProfile writes the profile and reads it back through the PUBLIC
// merchant endpoint, so persistence is confirmed by a different route than the one that
// wrote it. A handler that accepted the request and stored nothing would still 200.
func TestLive_SetMerchantProfile(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.useAPI(t, api)

	want := "REF-251 live profile " + strconv.FormatInt(time.Now().Unix(), 10)

	_, out, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{
		MerchantID:     e.merchantID,
		Description:    want,
		LandingPageURL: "https://example.com/ref-251",
	})
	if err != nil {
		t.Fatalf("set_merchant_profile: %v", err)
	}
	if out.Description != want {
		t.Errorf("returned description = %q, want %q", out.Description, want)
	}

	resp, err := http.Get(api + "/v1/merchant/" + e.merchantID)
	if err != nil {
		t.Fatalf("public merchant read: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public merchant read returned %d", resp.StatusCode)
	}

	var public map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&public); err != nil {
		t.Fatalf("decode public merchant: %v", err)
	}
	if got, _ := public["description"].(string); got != want {
		t.Fatalf("the profile did not persist: public description = %q, want %q", got, want)
	}
}

// TestLive_CheckProductReadiness proves the probe endpoint answers this client. pass is
// NOT asserted: whether the fixture's endpoint is correctly wired is the fixture's
// business, and a false here is a successful probe.
func TestLive_CheckProductReadiness(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.useAPI(t, api)

	resource := os.Getenv("MERCHANT_LIVE_RESOURCE")
	if resource == "" {
		t.Skip("MERCHANT_LIVE_RESOURCE not set; skipping the readiness probe (it needs a " +
			"product endpoint URL to probe).")
	}

	_, out, err := handleCheckProductReadiness(t.Context(), nil, checkProductReadinessInput{
		MerchantID: e.merchantID,
		Resource:   resource,
	})
	if err != nil {
		t.Fatalf("check_product_readiness: %v", err)
	}
	if len(out.Checks) == 0 {
		t.Fatal("the probe returned no checks — the response shape is not what this tool decodes")
	}
	for _, c := range out.Checks {
		if c.Name == "" {
			t.Errorf("a check came back unnamed: %+v", c)
		}
	}
}
