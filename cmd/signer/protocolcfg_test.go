package main

import (
	"context"
	"errors"
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
