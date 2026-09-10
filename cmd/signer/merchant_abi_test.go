package main

import (
	"encoding/hex"
	"math/big"
	"testing"
)

// Selectors and the golden getProduct return blob below come from the compiled
// MerchantRegistry / ProductRegistry artifacts, cross-checked against `cast sig` and
// `cast abi-encode` — two independent encoders, neither of them this ABI literal.
//
// Nothing in this repo compiles against the Solidity. The literals in main.go are a
// hand-written mirror, and a wrong one produces a call the node accepts and the contract
// rejects (or worse, dispatches to a different function). Selectors are the cheapest place
// to catch that, so they are pinned rather than derived.
var merchantSelectors = []struct {
	abiName  string
	method   string
	sig      string
	selector string
}{
	{"merchantRegistryABI", "setActive", "setActive(uint256,bool)", "e60a955d"},
	{"merchantRegistryABI", "isActive", "isActive(uint256)", "82afd23b"},
	{"productRegistryABI", "addProduct", "addProduct(uint256,bytes32,uint16,uint8,string)", "f5aad229"},
	{"productRegistryABI", "setCommission", "setCommission(uint256,bytes32,uint16)", "c16df641"},
	{"productRegistryABI", "setProductActive", "setProductActive(uint256,bytes32,bool)", "c7482c28"},
	{"productRegistryABI", "getProduct", "getProduct(uint256,bytes32)", "8dfcebc6"},
}

func TestMerchantABIs_Selectors(t *testing.T) {
	for _, tc := range merchantSelectors {
		t.Run(tc.abiName+"."+tc.method, func(t *testing.T) {
			var method = merchantRegistryABI.Methods[tc.method]
			if tc.abiName == "productRegistryABI" {
				method = productRegistryABI.Methods[tc.method]
			}
			if method.Name == "" {
				t.Fatalf("%s has no method %q", tc.abiName, tc.method)
			}

			if got := hex.EncodeToString(method.ID); got != tc.selector {
				t.Errorf("selector = %s, want %s\n\nThe literal in main.go does not describe %s.",
					got, tc.selector, tc.sig)
			}
			if got := method.Sig; got != tc.sig {
				t.Errorf("signature = %s, want %s", got, tc.sig)
			}
		})
	}
}

// TestProductRegistryABI_AddProductArgOrder pins the argument order of the one call with
// enough arguments to get them wrong. commissionBps and productType are both small
// unsigned integers, so a swap between them is a plausible edit that the selector would
// catch, but a swap of two same-width fields inside a future signature would not — this
// asserts the values themselves land where they are named.
func TestProductRegistryABI_AddProductArgOrder(t *testing.T) {
	var (
		merchantID = big.NewInt(4)
		productID  = [32]byte{31: 0xab}
		commission = uint16(750)
		cardURI    = "ipfs://cardcid"
	)

	data, err := productRegistryABI.Pack("addProduct", merchantID, productID, commission, productTypeOneOff, cardURI)
	if err != nil {
		t.Fatalf("Pack addProduct: %v", err)
	}

	args, err := productRegistryABI.Methods["addProduct"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack addProduct: %v", err)
	}
	if len(args) != 5 {
		t.Fatalf("got %d args, want 5", len(args))
	}

	if got := args[0].(*big.Int); got.Cmp(merchantID) != 0 {
		t.Errorf("merchantId = %s, want %s", got, merchantID)
	}
	if got := args[1].([32]byte); got != productID {
		t.Errorf("productId = %x, want %x", got, productID)
	}
	if got := args[2].(uint16); got != commission {
		t.Errorf("commissionBps = %d, want %d", got, commission)
	}
	if got := args[3].(uint8); got != productTypeOneOff {
		t.Errorf("productType = %d, want %d", got, productTypeOneOff)
	}
	if got := args[4].(string); got != cardURI {
		t.Errorf("productCardURI = %q, want %q", got, cardURI)
	}
}

// goldenProductReturn is `cast abi-encode` output for a Product with distinguishable field
// values. It stands in for a real getProduct return: the struct is a dynamic tuple, so word
// 0 is an offset and every field sits one slot later than a naive reading expects.
const goldenProductReturn = "0000000000000000000000000000000000000000000000000000000000000020" +
	"0000000000000000000000000000000000000000000000000000000000000004" +
	"00000000000000000000000000000000000000000000000000000000000000ab" +
	"00000000000000000000000000000000000000000000000000000000000002ee" +
	"0000000000000000000000000000000000000000000000000000000000000001" +
	"00000000000000000000000000000000000000000000000000000000000000e0" +
	"000000000000000000000000000000000000000000000000000000006553f100" +
	"0000000000000000000000000000000000000000000000000000000000000001" +
	"000000000000000000000000000000000000000000000000000000000000000e" +
	"697066733a2f2f63617264636964000000000000000000000000000000000000"

func TestProductRegistryABI_GetProductDecodesGolden(t *testing.T) {
	raw, err := hex.DecodeString(goldenProductReturn)
	if err != nil {
		t.Fatalf("decode golden: %v", err)
	}

	out, err := productRegistryABI.Unpack("getProduct", raw)
	if err != nil {
		t.Fatalf("Unpack getProduct: %v\n\nThe Product tuple in main.go does not match the "+
			"struct the contract returns — field order or a field's width has drifted.", err)
	}
	if len(out) != 1 {
		t.Fatalf("got %d outputs, want 1", len(out))
	}

	// Anonymous struct because abi.Unpack builds one from the component names; matching it
	// by field is what proves the literal's ORDER, not just its arity.
	got, ok := out[0].(struct {
		MerchantId     *big.Int `json:"merchantId"`
		ProductId      [32]byte `json:"productId"`
		CommissionBps  uint16   `json:"commissionBps"`
		Active         bool     `json:"active"`
		ProductCardURI string   `json:"productCardURI"`
		CreatedAt      *big.Int `json:"createdAt"`
		ProductType    uint8    `json:"productType"`
	})
	if !ok {
		t.Fatalf("getProduct output is %T, want the Product struct — the tuple components in "+
			"main.go differ from IProductRegistry.Product", out[0])
	}

	if got.MerchantId.Int64() != 4 {
		t.Errorf("merchantId = %s, want 4", got.MerchantId)
	}
	if want := ([32]byte{31: 0xab}); got.ProductId != want {
		t.Errorf("productId = %x, want %x", got.ProductId, want)
	}
	if got.CommissionBps != 750 {
		t.Errorf("commissionBps = %d, want 750", got.CommissionBps)
	}
	if !got.Active {
		t.Error("active = false, want true")
	}
	if got.ProductCardURI != "ipfs://cardcid" {
		t.Errorf("productCardURI = %q, want %q", got.ProductCardURI, "ipfs://cardcid")
	}
	if got.CreatedAt.Int64() != 1700000000 {
		t.Errorf("createdAt = %s, want 1700000000", got.CreatedAt)
	}
	if got.ProductType != productTypeOneOff {
		t.Errorf("productType = %d, want %d", got.ProductType, productTypeOneOff)
	}
}

// TestMerchantABIs_AreMinimal fails when an entry is added to either literal without a
// caller. Both ABIs are hand-maintained mirrors, so every entry is a claim about the
// deployed contract that something has to check; an unused one is an unchecked claim.
func TestMerchantABIs_AreMinimal(t *testing.T) {
	known := map[string]bool{}
	for _, tc := range merchantSelectors {
		known[tc.abiName+"."+tc.method] = true
	}

	for name := range merchantRegistryABI.Methods {
		if !known["merchantRegistryABI."+name] {
			t.Errorf("merchantRegistryABI has %q with no pinned selector — add it to "+
				"merchantSelectors, or drop it from the literal", name)
		}
	}
	for name := range productRegistryABI.Methods {
		if !known["productRegistryABI."+name] {
			t.Errorf("productRegistryABI has %q with no pinned selector — add it to "+
				"merchantSelectors, or drop it from the literal", name)
		}
	}
}

// TestMerchantABIs_NoEvents documents that neither literal declares events. Nothing parses
// a merchant receipt's logs: addProduct takes the productId as an input rather than
// assigning one, and setActive is confirmed by reading isActive back. An event appearing
// here means a tool started depending on log decoding, which needs its topic pinned the
// way the selectors above are.
func TestMerchantABIs_NoEvents(t *testing.T) {
	for _, a := range []struct {
		name string
		evs  int
	}{
		{"merchantRegistryABI", len(merchantRegistryABI.Events)},
		{"productRegistryABI", len(productRegistryABI.Events)},
	} {
		if a.evs != 0 {
			t.Errorf("%s declares %d event(s); pin the topic hash before relying on it",
				a.name, a.evs)
		}
	}
}

// TestMerchantABIs_ParseCleanly guards the literals against JSON that parses to nothing.
// mustParseABI panics on malformed JSON but accepts a valid empty array, which would make
// every Pack fail at runtime with "method not found" instead of at startup.
func TestMerchantABIs_ParseCleanly(t *testing.T) {
	if len(merchantRegistryABI.Methods) != 2 {
		t.Errorf("merchantRegistryABI has %d methods, want 2", len(merchantRegistryABI.Methods))
	}
	if len(productRegistryABI.Methods) != 4 {
		t.Errorf("productRegistryABI has %d methods, want 4", len(productRegistryABI.Methods))
	}
}
