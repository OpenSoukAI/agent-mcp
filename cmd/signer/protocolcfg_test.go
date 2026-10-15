package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestConfiguredChainID_DefaultsToSepolia(t *testing.T) {
	t.Setenv("CHAIN_ID", "")
	got, err := configuredChainID()
	if err != nil {
		t.Fatal(err)
	}
	if got != 84532 {
		t.Fatalf("got %d, want 84532", got)
	}
}

func TestConfiguredChainID_ReadsEnv(t *testing.T) {
	t.Setenv("CHAIN_ID", "8453")
	got, err := configuredChainID()
	if err != nil || got != 8453 {
		t.Fatalf("got %d, %v", got, err)
	}
}

func TestConfiguredChainID_RejectsGarbage(t *testing.T) {
	t.Setenv("CHAIN_ID", "base")
	if _, err := configuredChainID(); err == nil {
		t.Fatal("want error for non-numeric CHAIN_ID")
	}
}

func TestProtocolKey_EnvVarNames(t *testing.T) {
	cases := map[protocolKey]string{
		keyReviewRegistry:   "REVIEW_REGISTRY_ADDRESS",
		keyEscrow:           "COMMISSION_ESCROW_ADDRESS",
		keyMerchantRegistry: "MERCHANT_REGISTRY_ADDRESS",
		keyProductRegistry:  "PRODUCT_REGISTRY_ADDRESS",
		keySplitRouter:      "SPLIT_ROUTER_ADDRESS",
	}
	for k, want := range cases {
		if got := k.envVar(); got != want {
			t.Errorf("%s: got %q want %q", k, got, want)
		}
	}
}

func TestResolveAddress_EnvOverrideWinsWithoutRPC(t *testing.T) {
	resetAddressCache()
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "0x1111111111111111111111111111111111111111")
	calls := 0
	orig := callPAR
	callPAR = func(ctx context.Context, chainID int64, par common.Address, key protocolKey) (common.Address, error) {
		calls++
		return common.Address{}, errors.New("must not be called")
	}
	t.Cleanup(func() { callPAR = orig })

	got, err := resolveAddress(context.Background(), 84532, keyReviewRegistry)
	if err != nil {
		t.Fatal(err)
	}
	if got != common.HexToAddress("0x1111111111111111111111111111111111111111") {
		t.Fatalf("got %s", got.Hex())
	}
	if calls != 0 {
		t.Fatalf("PAR called %d times with env override set", calls)
	}
}

func TestResolveAddress_FallsBackToPARAndCaches(t *testing.T) {
	resetAddressCache()
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "")
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "")
	want := common.HexToAddress("0x2222222222222222222222222222222222222222")
	calls := 0
	orig := callPAR
	callPAR = func(ctx context.Context, chainID int64, par common.Address, key protocolKey) (common.Address, error) {
		calls++
		if chainID != 84532 || key != keyReviewRegistry {
			t.Fatalf("unexpected lookup chain=%d key=%s", chainID, key)
		}
		if par != common.HexToAddress("0xe6383d10EDb4c86F72d8327973d246680FFdDDdA") {
			t.Fatalf("unexpected PAR %s", par.Hex())
		}
		return want, nil
	}
	t.Cleanup(func() { callPAR = orig })

	for i := 0; i < 3; i++ {
		got, err := resolveAddress(context.Background(), 84532, keyReviewRegistry)
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("got %s", got.Hex())
		}
	}
	if calls != 1 {
		t.Fatalf("PAR called %d times, want 1 (cached)", calls)
	}
}

func TestResolveAddress_PAREnvOverride(t *testing.T) {
	resetAddressCache()
	t.Setenv("COMMISSION_ESCROW_ADDRESS", "")
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "0x3333333333333333333333333333333333333333")
	orig := callPAR
	callPAR = func(ctx context.Context, chainID int64, par common.Address, key protocolKey) (common.Address, error) {
		if par != common.HexToAddress("0x3333333333333333333333333333333333333333") {
			t.Fatalf("PAR override ignored, got %s", par.Hex())
		}
		return common.HexToAddress("0x4444444444444444444444444444444444444444"), nil
	}
	t.Cleanup(func() { callPAR = orig })
	if _, err := resolveAddress(context.Background(), 31337, keyEscrow); err != nil {
		t.Fatal(err)
	}
}

func TestResolveAddress_UnknownChainNoOverrideErrors(t *testing.T) {
	resetAddressCache()
	t.Setenv("COMMISSION_ESCROW_ADDRESS", "")
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "")
	_, err := resolveAddress(context.Background(), 31337, keyEscrow)
	if err == nil {
		t.Fatal("want error")
	}
	for _, s := range []string{"31337", "PROTOCOL_ADDRESS_REGISTRY", "COMMISSION_ESCROW_ADDRESS"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q should name %q", err, s)
		}
	}
}

func TestResolveAddress_PARZeroIsError(t *testing.T) {
	resetAddressCache()
	t.Setenv("PRODUCT_REGISTRY_ADDRESS", "")
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "")
	orig := callPAR
	callPAR = func(ctx context.Context, chainID int64, par common.Address, key protocolKey) (common.Address, error) {
		return common.Address{}, nil
	}
	t.Cleanup(func() { callPAR = orig })
	_, err := resolveAddress(context.Background(), 84532, keyProductRegistry)
	if err == nil || !strings.Contains(err.Error(), "PRODUCT_REGISTRY") {
		t.Fatalf("want error naming the key, got %v", err)
	}
}

func TestAttestationOrigin_EnvWins(t *testing.T) {
	t.Setenv("ATTESTATION_ORIGIN", "https://api.example.test/")
	got, err := attestationOrigin(84532)
	if err != nil || got != "https://api.example.test" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAttestationOrigin_MainnetDefault(t *testing.T) {
	t.Setenv("ATTESTATION_ORIGIN", "")
	got, err := attestationOrigin(8453)
	if err != nil || got != "https://api.opensouk.ai" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAttestationOrigin_UnknownChainNeedsEnv(t *testing.T) {
	t.Setenv("ATTESTATION_ORIGIN", "")
	_, err := attestationOrigin(31337)
	if err == nil || !strings.Contains(err.Error(), "ATTESTATION_ORIGIN") {
		t.Fatalf("want error naming the env var, got %v", err)
	}
}

func TestAttestationOrigin_RejectsBareHost(t *testing.T) {
	t.Setenv("ATTESTATION_ORIGIN", "api.example.test")
	if _, err := attestationOrigin(84532); err == nil {
		t.Fatal("want error: origin needs a scheme")
	}
}

func TestWarnAddressOverrides_KnownChainWarns(t *testing.T) {
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "0x1111111111111111111111111111111111111111")
	t.Setenv("COMMISSION_ESCROW_ADDRESS", "")
	var buf bytes.Buffer
	warnAddressOverrides(84532, &buf)
	out := buf.String()
	if !strings.Contains(out, "REVIEW_REGISTRY_ADDRESS") || strings.Contains(out, "COMMISSION_ESCROW_ADDRESS") {
		t.Fatalf("want a warning naming only the set override, got %q", out)
	}
}

func TestWarnAddressOverrides_UnknownChainSilent(t *testing.T) {
	t.Setenv("REVIEW_REGISTRY_ADDRESS", "0x1111111111111111111111111111111111111111")
	var buf bytes.Buffer
	warnAddressOverrides(31337, &buf)
	if buf.Len() != 0 {
		t.Fatalf("anvil-style chain must not warn, got %q", buf.String())
	}
}

// TestNoRequireAddrLeft: every contract address comes from resolveAddress (env override, else
// the ProtocolAddressRegistry); a surviving requireAddr call would reintroduce a hand-typed
// address with no registry fallback.
func TestNoRequireAddrLeft(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "requireAddr(") {
			t.Errorf("%s still calls requireAddr; use resolveAddress", f)
		}
	}
}

func TestAttestationOrigin_TestnetDefault(t *testing.T) {
	t.Setenv("ATTESTATION_ORIGIN", "")
	got, err := attestationOrigin(84532)
	if err != nil || got != "https://api.sysdev.wtf" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestResolveAddress_RejectsMalformedOverride(t *testing.T) {
	for _, bad := range []string{"0x1234", "garbage", "0xZZ"} {
		resetAddressCache()
		t.Setenv("REVIEW_REGISTRY_ADDRESS", bad)
		_, err := resolveAddress(context.Background(), 84532, keyReviewRegistry)
		if err == nil || !strings.Contains(err.Error(), "REVIEW_REGISTRY_ADDRESS") {
			t.Fatalf("override %q: want error naming the env var, got %v", bad, err)
		}
	}
}

func TestResolveAddress_RejectsZeroOverride(t *testing.T) {
	resetAddressCache()
	t.Setenv("COMMISSION_ESCROW_ADDRESS", "0x0000000000000000000000000000000000000000")
	_, err := resolveAddress(context.Background(), 84532, keyEscrow)
	if err == nil || !strings.Contains(err.Error(), "COMMISSION_ESCROW_ADDRESS") {
		t.Fatalf("want error naming the env var, got %v", err)
	}
}

func TestParAddressFor_RejectsMalformedOverride(t *testing.T) {
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "not-an-address")
	_, err := parAddressFor(84532)
	if err == nil || !strings.Contains(err.Error(), "PROTOCOL_ADDRESS_REGISTRY") {
		t.Fatalf("want error naming the env var, got %v", err)
	}
}

// TestParGetAddress_NoContractAtPAR: an RPC whose chain has no contract at the registry
// address answers eth_call with empty data. That is a configuration error (wrong PAR for
// this RPC), and the message must say so rather than surface an ABI decode failure.
func TestParGetAddress_NoContractAtPAR(t *testing.T) {
	rpc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":"0x"}`, req.ID)
	}))
	t.Cleanup(rpc.Close)
	t.Setenv("BASE_RPC_URL", rpc.URL)
	_, err := parGetAddress(context.Background(), 84532, common.HexToAddress("0xe6383d10EDb4c86F72d8327973d246680FFdDDdA"), keySplitRouter)
	if err == nil || !strings.Contains(err.Error(), "no contract") || !strings.Contains(err.Error(), "PROTOCOL_ADDRESS_REGISTRY") {
		t.Fatalf("want a no-contract error naming PROTOCOL_ADDRESS_REGISTRY, got %v", err)
	}
}
