package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

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
