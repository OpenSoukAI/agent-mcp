package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
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

// readProduct calls getProduct on the fixture's product.
func (e liveEnv) readProduct(t *testing.T) (commissionBps uint16, active bool, productType uint8) {
	t.Helper()
	return e.readProductAt(t, e.productID)
}

// readProductAt calls getProduct and returns the fields the tools change.
func (e liveEnv) readProductAt(t *testing.T, productIDHex string) (commissionBps uint16, active bool, productType uint8) {
	t.Helper()

	client, _, err := dialChain(context.Background(), e.chainID)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	productID, err := parseProductID(productIDHex)
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

// ensureActivated runs activate_merchant against the REAL backend so the tests that need a
// registered merchant have one. It is a precondition, not the subject: without it those
// tests fail with a 409 or 404 that says nothing about the code under test.
func (e liveEnv) ensureActivated(t *testing.T, api string) {
	t.Helper()

	e.useAPI(t, api)
	if _, _, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	}); err != nil {
		t.Fatalf("precondition: activate_merchant against %s: %v", api, err)
	}
}

// TestLive_ActivateMerchant_AgainstRealBackend is the composite's only unscripted run. The
// other activation tests script the backend so they can force its failures, which means
// none of them check that a REAL /v1/agent/register and /v1/merchant/register accept what
// this tool sends — the status codes, the field names, and the order.
func TestLive_ActivateMerchant_AgainstRealBackend(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.useAPI(t, api)

	_, out, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	})
	if err != nil {
		t.Fatalf("activate_merchant: %v", err)
	}
	if out.AgentRegistered == "" || out.MerchantRegistered == "" {
		t.Fatalf("a registration step reported nothing: %+v", out)
	}
	if !e.readMerchantActive(t) {
		t.Fatal("the merchant is not active on-chain")
	}

	// Re-run: against the real backend both registrations must now come back as conflicts,
	// which is what makes the retry instruction true rather than merely plausible.
	_, again, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	})
	if err != nil {
		t.Fatalf("re-running activate_merchant against the real backend failed: %v", err)
	}
	if again.AgentRegistered != "already_registered" || again.MerchantRegistered != "already_registered" {
		t.Errorf("the real backend's repeat responses were not folded into success: agent=%q merchant=%q",
			again.AgentRegistered, again.MerchantRegistered)
	}
	if again.TxHash != "" {
		t.Errorf("the second run sent a transaction (%s)", again.TxHash)
	}
}

func TestLive_GetMerchantStats(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.ensureActivated(t, api)

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
	e.ensureActivated(t, api)

	want := "REF-251 live profile " + strconv.FormatInt(time.Now().Unix(), 10)

	_, out, err := handleSetMerchantProfile(t.Context(), nil, setMerchantProfileInput{
		MerchantID:     e.merchantID,
		Description:    &want,
		LandingPageURL: strPtr("https://example.com/ref-251"),
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

// ── Live composite tests ────────────────────────────────────────────────────────
//
// These use the REAL chain and an in-test backend. That split is deliberate: what the
// composites add over their parts is chain-state awareness — skip the write when the flag
// is already set, skip addProduct when the product exists — and only a real chain has
// state. The backend side is scripted because the interesting cases are its FAILURES,
// which a running backend will not produce on demand.

// fakeAPIFor points the REST half at a scripted backend while the chain half stays real.
func (e liveEnv) fakeAPIFor(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	e.use(t, e.ownerKeyHex)
	t.Setenv("REFERRER_API_URL", srv.URL)
	return srv
}

// setMerchantActiveDirect forces the on-chain flag so a test can start from a KNOWN state.
// Without it these tests inherit whatever an earlier run left behind: a merchant that is
// already active makes activate_merchant skip its transaction, and the assertions about a
// spent-gas failure then pass without ever reaching that branch.
func (e liveEnv) setMerchantActiveDirect(t *testing.T, active bool) {
	t.Helper()

	w := merchantWrite{
		tool:    "test_setup",
		addrEnv: "MERCHANT_REGISTRY_ADDRESS",
		abi:     merchantRegistryABI,
		method:  "setActive",
		reverts: setMerchantActiveRevertTable,
		advice:  "test setup",
	}
	if _, _, err := w.send(context.Background(), mustBigInt(t, e.merchantID), e.chainID,
		mustBigInt(t, e.merchantID), active); err != nil {
		t.Fatalf("test setup: setActive(%v): %v", active, err)
	}
}

// registrationsCreated answers 201 to both registration endpoints.
func registrationsCreated(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, _ = w.Write([]byte(`{}`))
}

// TestLive_ActivateMerchant_IsIdempotent runs the whole composite twice. The second run is
// what a resumed activation looks like, and it must succeed without sending a transaction —
// that is the only thing that makes "call it again" a usable retry instruction.
func TestLive_ActivateMerchant_IsIdempotent(t *testing.T) {
	e := liveMerchantEnv(t)

	var conflictAfterFirst bool
	e.fakeAPIFor(t, func(w http.ResponseWriter, r *http.Request) {
		if conflictAfterFirst {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"error":"already registered"}`))
			return
		}
		registrationsCreated(w, r)
	})

	// Start from inactive, so the first run genuinely sends the transaction the second run
	// must skip. Inheriting an already-active merchant would make both runs identical and
	// the idempotency claim untested.
	e.setMerchantActiveDirect(t, false)

	_, out, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	})
	if err != nil {
		t.Fatalf("activate_merchant: %v", err)
	}
	if out.AlreadyActive {
		t.Error("already_active = true on the first run, from an inactive merchant")
	}
	if out.TxHash == "" {
		t.Fatal("the first run sent no transaction from an inactive merchant")
	}
	if !e.readMerchantActive(t) {
		t.Fatal("the merchant is not active on-chain after activate_merchant")
	}

	// Second run: the flag is set now, so no transaction may be sent, and the backend's 409s
	// must read as success.
	conflictAfterFirst = true
	_, again, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	})
	if err != nil {
		t.Fatalf("re-running activate_merchant failed, so a half-finished activation cannot be "+
			"resumed: %v", err)
	}
	if !again.AlreadyActive {
		t.Error("already_active = false on the second run")
	}
	if again.TxHash != "" {
		t.Errorf("the second run sent a transaction (%s) — a retry must not cost gas", again.TxHash)
	}
	if again.AgentRegistered != "already_registered" || again.MerchantRegistered != "already_registered" {
		t.Errorf("409s were not folded into success: agent=%q merchant=%q",
			again.AgentRegistered, again.MerchantRegistered)
	}
	if out.MerchantID != e.merchantID {
		t.Errorf("merchant_id = %q", out.MerchantID)
	}
}

// TestLive_ActivateMerchant_SyncFailureIsRecoverable is the REF-254 hazard on the activation
// path: the chain write lands and the backend does not. The error has to say the gas is
// spent and that repeating the call is safe, and repeating it has to actually work.
func TestLive_ActivateMerchant_SyncFailureIsRecoverable(t *testing.T) {
	e := liveMerchantEnv(t)

	failing := true
	e.fakeAPIFor(t, func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
			return
		}
		registrationsCreated(w, r)
	})

	// Inactive first, so the failure happens AFTER a real transaction. Against an
	// already-active merchant the tool sends nothing, and the "gas is spent" wording — the
	// part that matters — is never produced.
	e.setMerchantActiveDirect(t, false)

	_, _, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	})
	if err == nil {
		t.Fatal("a 500 from the backend was reported as success")
	}
	for _, want := range []string{"STATE:", "SUCCEEDED", "gas is spent", "activate_merchant again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}

	// The chain half must have landed regardless.
	if !e.readMerchantActive(t) {
		t.Fatal("the on-chain flag is not set, so the reported STATE was wrong")
	}

	// And the retry the message promises must succeed.
	failing = false
	if _, _, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	}); err != nil {
		t.Fatalf("the retry the error instructed the agent to make failed: %v", err)
	}
}

// freshProductID derives a product id no earlier run has used, so add_product's create path
// is genuinely exercised rather than always taking the already-exists branch.
func freshProductID(t *testing.T) string {
	t.Helper()
	h := crypto.Keccak256([]byte("ref-251-live-" + t.Name() + "-" + strconv.FormatInt(time.Now().UnixNano(), 10)))
	return "0x" + hex.EncodeToString(h)
}

// TestLive_AddProduct_CreateThenRepeat covers both branches in one run: a product that does
// not exist is written on-chain, and the same call repeated skips the write. The skip is
// what makes the sync retryable at all — addProduct on its own reverts ProductAlreadyExists.
func TestLive_AddProduct_CreateThenRepeat(t *testing.T) {
	e := liveMerchantEnv(t)

	var syncCalls int
	e.fakeAPIFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/merchant/product" {
			syncCalls++
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})

	productID := freshProductID(t)
	in := addProductInput{
		MerchantID:    e.merchantID,
		ProductID:     productID,
		CommissionBps: 750,
		EndpointURL:   "https://shop.example/buy",
		Name:          "Live Widget",
		Category:      "test",
		ChainID:       e.chainID,
	}

	_, created, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("add_product (create): %v", err)
	}
	if created.AlreadyOnChain {
		t.Error("already_on_chain = true for a product id never used before")
	}
	if created.TxHash == "" {
		t.Error("no transaction was sent for a new product")
	}
	if !created.MetadataSynced {
		t.Error("metadata_synced = false")
	}
	if created.CommissionBps != 750 {
		t.Errorf("commission_bps = %d, want 750", created.CommissionBps)
	}

	// Confirm on-chain rather than trusting the output: the rate must really be 750.
	if got, _, err := readProductCommission(t.Context(), mustBigInt(t, e.merchantID),
		mustProductID(t, productID), e.chainID); err != nil || got != 750 {
		t.Fatalf("on-chain commission = %d (err %v), want 750", got, err)
	}

	// productType is the hand-mirrored enum ordinal: its member names are absent from the
	// ABI, so reordering the Solidity enum leaves everything compiling and green. This round
	// trip is the only thing that would catch it.
	if _, _, gotType := e.readProductAt(t, productID); gotType != productTypeRepeat {
		t.Fatalf("on-chain productType = %d, want Repeat (%d) — the enum ordinals mirrored in "+
			"main.go no longer match IProductRegistry.ProductType", gotType, productTypeRepeat)
	}

	_, repeat, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("add_product (repeat) failed, so a stranded product can never be synced: %v", err)
	}
	if !repeat.AlreadyOnChain {
		t.Error("already_on_chain = false on the repeat")
	}
	if repeat.TxHash != "" {
		t.Errorf("the repeat sent a transaction (%s) — addProduct would have reverted", repeat.TxHash)
	}
	if !repeat.MetadataSynced {
		t.Error("the repeat did not re-run the sync, which is the only reason to repeat")
	}
	if syncCalls != 2 {
		t.Errorf("the backend sync ran %d times, want 2", syncCalls)
	}
}

// TestLive_AddProduct_DoesNotRepriceSilently: repeating add_product with a different rate
// must not change it. Repricing is gated on a different role and moves money; doing it as a
// side effect of a call the agent believed was a create would be silent.
func TestLive_AddProduct_DoesNotRepriceSilently(t *testing.T) {
	e := liveMerchantEnv(t)
	e.fakeAPIFor(t, registrationsCreated)

	productID := freshProductID(t)
	in := addProductInput{
		MerchantID:    e.merchantID,
		ProductID:     productID,
		CommissionBps: 750,
		EndpointURL:   "https://shop.example/buy",
		Name:          "Live Widget",
		ChainID:       e.chainID,
	}
	if _, _, err := handleAddProduct(t.Context(), nil, in); err != nil {
		t.Fatalf("add_product (create): %v", err)
	}

	in.CommissionBps = 1500
	_, out, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("add_product (reprice attempt): %v", err)
	}
	if out.CommissionWarning == "" {
		t.Error("no warning for a rate that differs from the one on-chain")
	}
	if out.CommissionBps != 750 {
		t.Errorf("reported commission_bps = %d, want the on-chain 750", out.CommissionBps)
	}

	got, _, err := readProductCommission(t.Context(), mustBigInt(t, e.merchantID),
		mustProductID(t, productID), e.chainID)
	if err != nil {
		t.Fatalf("read commission: %v", err)
	}
	if got != 750 {
		t.Fatalf("the rate was changed to %d by a call that only asked to add the product", got)
	}
}

// TestLive_AddProduct_SyncFailureNamesRetry is the REF-254 hazard on the product path. A
// product on-chain with no backend metadata is payable and undiscoverable, and the agent
// cannot recover by calling addProduct again — so the message must point at this tool.
func TestLive_AddProduct_SyncFailureNamesRetry(t *testing.T) {
	e := liveMerchantEnv(t)

	failing := true
	e.fakeAPIFor(t, func(w http.ResponseWriter, r *http.Request) {
		if failing {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})

	productID := freshProductID(t)
	in := addProductInput{
		MerchantID:    e.merchantID,
		ProductID:     productID,
		CommissionBps: 600,
		EndpointURL:   "https://shop.example/buy",
		Name:          "Stranded Widget",
		ChainID:       e.chainID,
	}

	_, _, err := handleAddProduct(t.Context(), nil, in)
	if err == nil {
		t.Fatal("a failed sync was reported as success, leaving an undiscoverable product")
	}
	for _, want := range []string{"payable", "NOT discoverable", "add_product again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not mention %q: %v", want, err)
		}
	}

	// The product really is on-chain — the message claimed as much.
	if _, found, err := readProductCommission(t.Context(), mustBigInt(t, e.merchantID),
		mustProductID(t, productID), e.chainID); err != nil || !found {
		t.Fatalf("the product is NOT on-chain (found=%v, err=%v), so the reported STATE was wrong",
			found, err)
	}

	failing = false
	_, out, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("the retry the error instructed the agent to make failed: %v", err)
	}
	if !out.AlreadyOnChain || out.TxHash != "" {
		t.Errorf("the retry re-sent the chain write: already_on_chain=%v tx=%q",
			out.AlreadyOnChain, out.TxHash)
	}
	if !out.MetadataSynced {
		t.Error("the retry did not complete the sync")
	}
}

func mustProductID(t *testing.T, s string) [32]byte {
	t.Helper()
	id, err := parseProductID(s)
	if err != nil {
		t.Fatalf("parseProductID(%s): %v", s, err)
	}
	return id
}

// TestLive_ActivateMerchant_RegistersAgentBeforeMerchant pins the order THROUGH the
// composite. merchants carries a foreign key onto agents, so the reverse order fails on a
// constraint that names neither endpoint.
//
// It has to run against a chain because the composite reads chain state before it posts
// anything. An earlier version of this test called registerIdentity twice by hand instead —
// which asserted the test's own ordering and passed happily when the composite's order was
// swapped.
func TestLive_ActivateMerchant_RegistersAgentBeforeMerchant(t *testing.T) {
	e := liveMerchantEnv(t)

	var mu sync.Mutex
	var order []string

	e.fakeAPIFor(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.URL.Path)
		mu.Unlock()
		registrationsCreated(w, r)
	})

	if _, _, err := handleActivateMerchant(t.Context(), nil, activateMerchantInput{
		MerchantID: e.merchantID,
		ChainID:    e.chainID,
	}); err != nil {
		t.Fatalf("activate_merchant: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"/v1/agent/register", "/v1/merchant/register"}
	if len(order) != len(want) {
		t.Fatalf("the composite called %v, want exactly %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("call order = %v, want %v — merchants has a foreign key onto agents", order, want)
		}
	}
}

// TestLive_AddProduct_AgainstRealBackend is add_product's only unscripted run. The scripted
// tests force the backend's failures, so none of them check that a REAL
// POST /v1/merchant/product accepts what this tool sends — and that endpoint verifies the
// product exists ON-CHAIN before it will store the metadata, which only a real pairing of
// chain and backend exercises.
func TestLive_AddProduct_AgainstRealBackend(t *testing.T) {
	e := liveMerchantEnv(t)
	api := liveAPI(t)
	e.ensureActivated(t, api)

	productID := freshProductID(t)
	in := addProductInput{
		MerchantID:    e.merchantID,
		ProductID:     productID,
		CommissionBps: 900,
		EndpointURL:   "https://shop.example/buy",
		Name:          "REF-251 Real Widget",
		Description:   "added through add_product against a real backend",
		Category:      "test",
		ChainID:       e.chainID,
	}

	_, out, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("add_product: %v", err)
	}
	if out.TxHash == "" || out.AlreadyOnChain {
		t.Errorf("expected a fresh on-chain write: %+v", out)
	}
	if !out.MetadataSynced {
		t.Fatal("metadata_synced = false against a real backend")
	}

	// Read the product back through the PUBLIC endpoint, so persistence is confirmed by a
	// route other than the one that wrote it.
	resp, err := http.Get(api + "/v1/merchant/product?merchant_id=" + e.merchantID +
		"&product_id=" + productID)
	if err != nil {
		t.Fatalf("public product read: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("public product read returned %d — the metadata did not persist", resp.StatusCode)
	}

	var public map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&public); err != nil {
		t.Fatalf("decode public product: %v", err)
	}
	if got, _ := public["name"].(string); got != in.Name {
		t.Errorf("public name = %q, want %q", got, in.Name)
	}

	// And the repeat path against the real backend: no second chain write, sync repeated.
	_, again, err := handleAddProduct(t.Context(), nil, in)
	if err != nil {
		t.Fatalf("re-running add_product against the real backend failed: %v", err)
	}
	if !again.AlreadyOnChain || again.TxHash != "" {
		t.Errorf("the repeat re-sent the chain write: %+v", again)
	}
	if !again.MetadataSynced {
		t.Error("the repeat did not re-run the sync")
	}
}
