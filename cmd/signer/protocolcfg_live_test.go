package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestResolveAddress_LiveSepoliaPAR reads the five protocol addresses from the baked Base
// Sepolia ProtocolAddressRegistry over a real RPC. Gated: REF493_LIVE=1 and BASE_RPC_URL.
func TestResolveAddress_LiveSepoliaPAR(t *testing.T) {
	if os.Getenv("REF493_LIVE") != "1" || os.Getenv("BASE_RPC_URL") == "" {
		t.Skip("set REF493_LIVE=1 and BASE_RPC_URL to run")
	}
	for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter} {
		t.Setenv(k.envVar(), "")
	}
	t.Setenv("PROTOCOL_ADDRESS_REGISTRY", "")
	resetAddressCache()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, k := range []protocolKey{keyReviewRegistry, keyEscrow, keyMerchantRegistry, keyProductRegistry, keySplitRouter} {
		addr, err := resolveAddress(ctx, 84532, k)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		t.Logf("%-18s %s", k, addr.Hex())
	}
}
