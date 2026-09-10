package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// Custom-error selectors, pinned from `cast sig` and cross-checked against the error
// entries in the compiled MerchantRegistry / ProductRegistry ABIs.
//
// newRevertTable derives its keys by hashing the signature STRING, so a typo in a
// signature produces a table that is well-formed, never matches anything, and silently
// degrades every revert to the raw fallback. Nothing else would notice.
var merchantRevertSelectors = map[string]string{
	"Unauthorised(uint256,bytes32,address)": "5d28026f",
	"ProductNotFound(uint256,bytes32)":      "c45f3aa1",
	"InvalidRates(uint16)":                  "08ae7051",
	"NotMerchantOwner(uint256,address)":     "158c0a06",
	"MerchantIsSuspended(uint256)":          "3b8b2dc3",
	"MerchantNotFound(uint256)":             "6e40285d",
	"ProductAlreadyExists(uint256,bytes32)": "7349654f",
	"MerchantNotActive(uint256)":            "520d0252",
}

// revertTableSignatures re-derives which signatures a table was built from, by hashing
// every known signature and keeping those whose selector the table holds. A table entry
// whose selector matches nothing known means the signature string is wrong.
func revertTableSignatures(t *testing.T, name string, table revertTable) map[string]string {
	t.Helper()

	bySelector := map[string]string{}
	for sig, selector := range merchantRevertSelectors {
		bySelector[selector] = sig
	}

	out := map[string]string{}
	for selector, msg := range table {
		sig, ok := bySelector[selector]
		if !ok {
			t.Errorf("%s has an entry with selector %s that matches no error declared by "+
				"MerchantRegistry or ProductRegistry — the signature string is misspelled, so "+
				"this entry can never fire", name, selector)
			continue
		}
		out[sig] = msg
	}
	return out
}

func TestSetCommissionRevertTable_CoversTheReachableReverts(t *testing.T) {
	got := revertTableSignatures(t, "setCommissionRevertTable", setCommissionRevertTable)

	// setCommission's reachable reverts, in call order: the role check, the existence check,
	// then the rate bound.
	for _, sig := range []string{
		"Unauthorised(uint256,bytes32,address)",
		"ProductNotFound(uint256,bytes32)",
		"InvalidRates(uint16)",
	} {
		if _, ok := got[sig]; !ok {
			t.Errorf("setCommissionRevertTable is missing %s", sig)
		}
	}
	if len(got) != 3 {
		t.Errorf("setCommissionRevertTable has %d entries, want 3", len(got))
	}
}

// TestSetCommissionRevertTable_NamesTheCommissionRole is the reason the two product tables
// are not shared. Both contracts revert the same Unauthorised selector, but setCommission
// is gated on COMMISSION_MANAGER and setProductActive on PRODUCT_MANAGER — a merged table
// would tell half its callers to fix the wrong role.
func TestSetCommissionRevertTable_NamesTheCommissionRole(t *testing.T) {
	got := revertTableSignatures(t, "setCommissionRevertTable", setCommissionRevertTable)
	msg := got["Unauthorised(uint256,bytes32,address)"]

	if !strings.Contains(msg, "COMMISSION_MANAGER") {
		t.Errorf("Unauthorised advice does not name COMMISSION_MANAGER: %q", msg)
	}

	activeMsg := revertTableSignatures(t, "setProductActiveRevertTable", setProductActiveRevertTable)["Unauthorised(uint256,bytes32,address)"]
	if !strings.Contains(activeMsg, "PRODUCT_MANAGER") {
		t.Errorf("set_product_active's Unauthorised advice does not name PRODUCT_MANAGER: %q", activeMsg)
	}
	if msg == activeMsg {
		t.Error("both tools give identical advice for Unauthorised — the two roles are distinct " +
			"and the advice has to say which one is missing")
	}
}

func TestSetProductActiveRevertTable_CoversTheReachableReverts(t *testing.T) {
	got := revertTableSignatures(t, "setProductActiveRevertTable", setProductActiveRevertTable)

	for _, sig := range []string{
		"Unauthorised(uint256,bytes32,address)",
		"ProductNotFound(uint256,bytes32)",
	} {
		if _, ok := got[sig]; !ok {
			t.Errorf("setProductActiveRevertTable is missing %s", sig)
		}
	}
	// InvalidRates is unreachable from setProductActive — it takes no rate. An entry for it
	// would be advice that can never be shown.
	if _, ok := got["InvalidRates(uint16)"]; ok {
		t.Error("setProductActiveRevertTable maps InvalidRates, which setProductActive cannot revert")
	}
	if len(got) != 2 {
		t.Errorf("setProductActiveRevertTable has %d entries, want 2", len(got))
	}
}

// TestRevertTableLookup_DecodesEncodedArguments checks the mechanism end to end: real revert
// data carries ABI-encoded arguments after the selector, and the lookup must ignore them.
func TestRevertTableLookup_DecodesEncodedArguments(t *testing.T) {
	// ProductNotFound(4, 0x…ab) as a node would return it.
	data, err := hex.DecodeString("c45f3aa1" +
		"0000000000000000000000000000000000000000000000000000000000000004" +
		"00000000000000000000000000000000000000000000000000000000000000ab")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	msg, ok := setCommissionRevertTable.lookupData(data)
	if !ok {
		t.Fatal("ProductNotFound revert data did not match setCommissionRevertTable")
	}
	if !strings.Contains(msg, "add_product") {
		t.Errorf("ProductNotFound advice does not point at add_product: %q", msg)
	}
}

func TestParseMerchantID(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"4", "4", false},
		{" 4 ", "4", false},
		{"0", "0", false}, // register() returns 0 for the first identity on a registry
		{"-1", "", true},
		{"", "", true},
		{"0x4", "", true},
		{"four", "", true},
	}

	for _, tc := range cases {
		got, err := parseMerchantID(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseMerchantID(%q) = %s, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMerchantID(%q): %v", tc.in, err)
			continue
		}
		if got.String() != tc.want {
			t.Errorf("parseMerchantID(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

const validTestProductID = "0x00000000000000000000000000000000000000000000000000000000000000ab"

func TestParseProductID(t *testing.T) {
	const valid = validTestProductID

	got, err := parseProductID(valid)
	if err != nil {
		t.Fatalf("parseProductID(%s): %v", valid, err)
	}
	if want := ([32]byte{31: 0xab}); got != want {
		t.Errorf("parseProductID = %x, want %x", got, want)
	}

	// A short value must be REJECTED, not left-padded. Padding would silently retarget the
	// call at a different, valid, empty product slot — the contract would revert
	// ProductNotFound for an id the agent never asked about.
	for _, bad := range []string{
		"0xab",
		"0x" + strings.Repeat("ab", 31),
		"0x" + strings.Repeat("ab", 33),
		strings.Repeat("ab", 32), // no 0x prefix
		"0xzz" + strings.Repeat("ab", 31),
		"",
	} {
		if _, err := parseProductID(bad); err == nil {
			t.Errorf("parseProductID(%q) accepted a malformed id", bad)
		}
	}
}

func TestParseCommissionBps(t *testing.T) {
	for _, in := range []int{0, 1, 1000, 9999, 10000} {
		got, err := parseCommissionBps(in)
		if err != nil {
			t.Errorf("parseCommissionBps(%d): %v", in, err)
			continue
		}
		if int(got) != in {
			t.Errorf("parseCommissionBps(%d) = %d", in, got)
		}
	}

	// 10001 is the first value the contract rejects with InvalidRates, so it is the boundary
	// worth naming locally rather than paying gas to discover.
	for _, in := range []int{-1, 10001, 65536} {
		if _, err := parseCommissionBps(in); err == nil {
			t.Errorf("parseCommissionBps(%d) accepted an out-of-range rate", in)
		}
	}
}

// installMerchantKey gives the package's signerKeys an entry for merchant 4 and points the
// handlers at a configured-but-undialable chain. A call that passes validation therefore
// stops at the dial with a recognisable error, which is what lets the tests below tell
// "rejected the input" apart from "got further than it should have".
func installMerchantKey(t *testing.T) {
	t.Helper()

	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ks, err := parseKeystore("4:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("PRODUCT_REGISTRY_ADDRESS", "0x000000000000000000000000000000000000dEaD")
	t.Setenv("BASE_RPC_URL", "")
}

const errNoRPC = "BASE_RPC_URL"

// TestSetProductActive_ValidInputReachesTheChain is the control for the two tests after it.
// It pins where a well-formed call stops, so their assertions are known to be observing a
// rejected input rather than any error at all.
func TestSetProductActive_ValidInputReachesTheChain(t *testing.T) {
	installMerchantKey(t)

	active := true
	_, _, err := handleSetProductActive(t.Context(), nil, setProductActiveInput{
		MerchantID: "4",
		ProductID:  validTestProductID,
		Active:     &active,
	})
	if err == nil {
		t.Fatal("want the dial to fail with BASE_RPC_URL unset")
	}
	if !strings.Contains(err.Error(), errNoRPC) {
		t.Fatalf("a valid call stopped somewhere other than the dial: %v", err)
	}
}

// TestSetProductActive_ActiveIsRequired pins the pointer field's whole purpose: a missing
// `active` must fail instead of defaulting to false and delisting the product.
func TestSetProductActive_ActiveIsRequired(t *testing.T) {
	installMerchantKey(t)

	_, _, err := handleSetProductActive(t.Context(), nil, setProductActiveInput{
		MerchantID: "4",
		ProductID:  validTestProductID,
		// Active omitted.
	})
	if err == nil {
		t.Fatal("omitting active was accepted — a forgotten flag would delist the product")
	}
	if strings.Contains(err.Error(), errNoRPC) {
		t.Fatalf("omitting active fell through to the chain, so the flag defaulted: %v", err)
	}
	if !strings.Contains(err.Error(), "active is required") {
		t.Errorf("error does not name the missing field: %v", err)
	}
}

// TestSetProductActive_ValidatesBeforeSending checks the ordering that keeps a bad call
// free: inputs are parsed before the key lookup, the address read and the dial, so a
// malformed id reports the field rather than a connection failure.
func TestSetProductActive_ValidatesBeforeSending(t *testing.T) {
	installMerchantKey(t)

	active := true
	_, _, err := handleSetProductActive(t.Context(), nil, setProductActiveInput{
		MerchantID: "not-a-number",
		ProductID:  "0xab",
		Active:     &active,
	})
	if err == nil {
		t.Fatal("want an error for a malformed merchant_id")
	}
	if strings.Contains(err.Error(), errNoRPC) {
		t.Fatalf("a malformed merchant_id reached the chain: %v", err)
	}
	if !strings.Contains(err.Error(), "merchant_id") {
		t.Errorf("error does not name merchant_id: %v", err)
	}
}

func TestSetProductCommission_ValidatesBeforeSending(t *testing.T) {
	installMerchantKey(t)

	cases := []struct {
		name  string
		in    setProductCommissionInput
		field string
	}{
		{"bad merchant", setProductCommissionInput{MerchantID: "-1", ProductID: validTestProductID, CommissionBps: 500}, "merchant_id"},
		{"bad product", setProductCommissionInput{MerchantID: "4", ProductID: "0xab", CommissionBps: 500}, "product_id"},
		{"bad rate", setProductCommissionInput{MerchantID: "4", ProductID: validTestProductID, CommissionBps: 10001}, "commission_bps"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := handleSetProductCommission(t.Context(), nil, tc.in)
			if err == nil {
				t.Fatal("want an error")
			}
			if strings.Contains(err.Error(), errNoRPC) {
				t.Fatalf("a bad %s reached the chain: %v", tc.field, err)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error does not name %s: %v", tc.field, err)
			}
		})
	}
}
