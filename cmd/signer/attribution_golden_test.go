package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
)

// Golden attribution-token fixture, shared with the backend (REF-267).
//
// These bytes are IDENTICAL to backend/internal/signing/token_golden_test.go's fixture, on
// purpose. `attributionTokenVersion` here is a hand-copied mirror of the backend's
// `tokenVersion`, which is the same failure class as the hand-mirrored contract enum ordinals:
// the mirror drifts and both repos stay green, because nothing compares them.
//
// Sharing the fixture is what couples them. A bump in either repo fails the other's build:
// bump the backend and this token stops being mintable there while this test still demands it;
// bump this constant and this test rejects the backend's own output.
//
// A ref link IS the token — published in a review, stored, shared, documented as permanent.
// Nothing re-mints one. So a token this signer can no longer decode is a link an agent can
// never pay. NEVER regenerate these bytes to make a test pass.
//
// Limit worth knowing: this couples the two repos on the payload SHAPE, not on the constant.
// Each repo now fails on its OWN bump, but a backend-only bump does not fail agent-mcp CI and
// vice versa — they are separate Go modules that never compile against each other. Closing
// that needs a shared module for the token format, or a CI step in one repo that reads the
// others constant. Until then the shared fixture is the coupling: regenerating it in one repo
// makes the two copies differ, which is greppable but not automatic.
const (
	goldenTokenB64 = "eyJ2Ijo0LCJyZXZpZXdlckFnZW50SWQiOiIxIiwicmV2aWV3SWQiOiI3IiwibWVyY2hhbnRJZCI6IjIiLCJwcm9kdWN0SWQiOiIweGFiMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAiLCJsb2NrZWRDb21taXNzaW9uQnBzIjo1MDAsImNhc2hiYWNrT2ZDb21taXNzaW9uQnBzIjoyMDAwLCJwcm9kdWN0VHlwZSI6MCwiaXNzdWVkQXQiOjE3MDAwMDAwMDAsImNoYWluSWQiOjg0NTMyLCJzcGxpdFJvdXRlciI6IjB4MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA5OSIsIm1lcmNoYW50RW5kcG9pbnQiOiJodHRwczovL3Nob3AuZXhhbXBsZS9idXkiLCJzZXR1cFVybCI6Imh0dHBzOi8vc2V0dXAuZXhhbXBsZS5jb20ifaynbLsd8i3Eh6iPf3lUpJyAmSBUAkw8L3pClg-l22CoyAxjFGC6DTubi0JrXfDq_kIulyBOXGAVuL94ZPDafQk"

	// Public half of the backend fixture's signing seed, as /.well-known/opensouk
	// publishes it for exactly this local verification.
	goldenPubKeyHex = "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
)

// TestGoldenToken_DecodesAtTheEdge is the regression gate for pay_for_product's local decode.
func TestGoldenToken_DecodesAtTheEdge(t *testing.T) {
	tok, err := verifyAndDecodeToken(goldenTokenB64, goldenPubKeyHex)
	if err != nil {
		t.Fatalf("verifyAndDecodeToken: %v\n\nA token the backend mints can no longer be decoded "+
			"here, so pay_for_product cannot pay any existing ref link. Either this signer's "+
			"attributionTokenVersion has drifted from the backend's tokenVersion, or the payload "+
			"shape changed incompatibly. Do not regenerate the fixture.", err)
	}

	if tok.Version != attributionTokenVersion {
		t.Errorf("Version = %d, want %d", tok.Version, attributionTokenVersion)
	}
	if tok.MerchantEndpoint != "https://shop.example/buy" {
		t.Errorf("MerchantEndpoint = %q", tok.MerchantEndpoint)
	}
	if tok.SetupURL != "https://setup.example.com" {
		t.Errorf("SetupURL = %q", tok.SetupURL)
	}
	if tok.ChainID != 84532 {
		t.Errorf("ChainID = %d, want 84532", tok.ChainID)
	}
	if tok.SplitRouter != "0x0000000000000000000000000000000000000099" {
		t.Errorf("SplitRouter = %q", tok.SplitRouter)
	}
	if tok.ReviewID != "7" {
		t.Errorf("ReviewID = %q, want 7", tok.ReviewID)
	}
	if tok.CashbackOfCommissionBps != 2000 {
		t.Errorf("CashbackOfCommissionBps = %d, want 2000", tok.CashbackOfCommissionBps)
	}
}

// TestGoldenToken_MirrorsTheBackendVersion states the coupling in one assertion, so a drifted
// mirror fails with a message naming the cause rather than as a confusing decode error.
func TestGoldenToken_MirrorsTheBackendVersion(t *testing.T) {
	var probe struct {
		V int `json:"v"`
	}
	signed, err := base64.RawURLEncoding.DecodeString(goldenTokenB64)
	if err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	payload := signed[:len(signed)-ed25519.SignatureSize]
	if err := json.Unmarshal(payload, &probe); err != nil {
		t.Fatalf("fixture payload is not JSON: %v", err)
	}
	if probe.V != attributionTokenVersion {
		t.Fatalf("attributionTokenVersion = %d but the backend's golden token is v%d — this "+
			"mirror has drifted from backend/internal/signing.tokenVersion. Whichever side moved, "+
			"every ref link ever issued is now undecodable by the other.",
			attributionTokenVersion, probe.V)
	}
}
