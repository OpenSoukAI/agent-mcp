package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// signTestToken mirrors the backend signing envelope: JSON payload || 64-byte Ed25519
// signature, base64url (no padding). Field names match backend internal/signing.tokenJSON.
func signTestToken(t *testing.T, priv ed25519.PrivateKey, tok decodedAttributionToken) string {
	t.Helper()
	payload, err := json.Marshal(tok)
	if err != nil {
		t.Fatalf("marshal token: %v", err)
	}
	sig := ed25519.Sign(priv, payload)
	return base64.RawURLEncoding.EncodeToString(append(payload, sig...))
}

func validTestToken() decodedAttributionToken {
	return decodedAttributionToken{
		Version:                 attributionTokenVersion,
		ReviewerAgentID:         "7",
		ReviewID:                "42",
		MerchantID:              "3",
		ProductID:               "0x00000000000000000000000000000000000000000000000000000000000000aa",
		CashbackOfCommissionBps: 1500,
		ProductType:             1,
		IssuedAt:                1700000000,
		ChainID:                 84532,
		SplitRouter:             "0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E",
		MerchantEndpoint:        "https://merchant.example/buy",
		SetupURL:                "https://api.example/.well-known/opensouk",
	}
}

func TestVerifyAndDecodeToken_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := signTestToken(t, priv, validTestToken())

	got, err := verifyAndDecodeToken(raw, hex.EncodeToString(pub))
	if err != nil {
		t.Fatalf("verifyAndDecodeToken: %v", err)
	}
	if got.MerchantEndpoint != "https://merchant.example/buy" {
		t.Errorf("MerchantEndpoint = %q", got.MerchantEndpoint)
	}
	if got.SplitRouter != "0xC09996D8B5BA5509f129ea8a149b1930EfFCc04E" {
		t.Errorf("SplitRouter = %q", got.SplitRouter)
	}
	if got.ChainID != 84532 {
		t.Errorf("ChainID = %d", got.ChainID)
	}
	if got.CashbackOfCommissionBps != 1500 {
		t.Errorf("CashbackOfCommissionBps = %d", got.CashbackOfCommissionBps)
	}
}

func TestVerifyAndDecodeToken_BadSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := signTestToken(t, priv, validTestToken())
	// Flip a bit in the trailing signature.
	signed, _ := base64.RawURLEncoding.DecodeString(raw)
	signed[len(signed)-1] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(signed)

	if _, err := verifyAndDecodeToken(tampered, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected signature verification failure, got nil")
	}
}

func TestVerifyAndDecodeToken_TamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	raw := signTestToken(t, priv, validTestToken())
	signed, _ := base64.RawURLEncoding.DecodeString(raw)
	// Flip a byte inside the payload (not the signature) — signature must no longer verify.
	signed[0] ^= 0x01
	tampered := base64.RawURLEncoding.EncodeToString(signed)

	if _, err := verifyAndDecodeToken(tampered, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected verification failure on tampered payload, got nil")
	}
}

func TestVerifyAndDecodeToken_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	otherPub, _, _ := ed25519.GenerateKey(nil)
	raw := signTestToken(t, priv, validTestToken())

	if _, err := verifyAndDecodeToken(raw, hex.EncodeToString(otherPub)); err == nil {
		t.Fatal("expected failure verifying against a different key, got nil")
	}
}

func TestVerifyAndDecodeToken_WrongVersion(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := validTestToken()
	tok.Version = 3
	raw := signTestToken(t, priv, tok)

	if _, err := verifyAndDecodeToken(raw, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected unsupported-version error, got nil")
	}
}

func TestVerifyAndDecodeToken_ShortBlob(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	short := base64.RawURLEncoding.EncodeToString([]byte("tooshort"))
	if _, err := verifyAndDecodeToken(short, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected too-small blob error, got nil")
	}
}

func TestVerifyAndDecodeToken_BadSplitRouter(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	tok := validTestToken()
	tok.SplitRouter = "not-an-address"
	raw := signTestToken(t, priv, tok)

	if _, err := verifyAndDecodeToken(raw, hex.EncodeToString(pub)); err == nil {
		t.Fatal("expected invalid splitRouter error, got nil")
	}
}

func TestSplitRefPath(t *testing.T) {
	cases := []struct {
		in        string
		wantChain string
		wantTok   string
		wantErr   bool
	}{
		{"abc123", "", "abc123", false},
		{"42431/abc123", "42431", "abc123", false},
		{"/abc123", "", "abc123", false},
		{"", "", "", true},
		{"a/b/c", "", "", true},
	}
	for _, c := range cases {
		chain, tok, err := splitRefPath(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("splitRefPath(%q) err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err == nil && (chain != c.wantChain || tok != c.wantTok) {
			t.Errorf("splitRefPath(%q) = (%q,%q), want (%q,%q)", c.in, chain, tok, c.wantChain, c.wantTok)
		}
	}
}

func TestBuyerAgentIDOrSentinel(t *testing.T) {
	// type(uint256).max — MUST equal the on-chain ProtocolConstants.SENTINEL_BUYER.
	const uint256Max = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
	if sentinelBuyerAgentID != uint256Max {
		t.Fatalf("sentinelBuyerAgentID = %s, want type(uint256).max %s", sentinelBuyerAgentID, uint256Max)
	}
	if got := buyerAgentIDOrSentinel("34"); got != "34" {
		t.Errorf("real agent_id: got %q, want 34", got)
	}
	if got := buyerAgentIDOrSentinel(""); got != sentinelBuyerAgentID {
		t.Errorf("empty agent_id: got %q, want sentinel", got)
	}
	if got := buyerAgentIDOrSentinel("   "); got != sentinelBuyerAgentID {
		t.Errorf("blank agent_id: got %q, want sentinel", got)
	}
}

func TestAttestationPubKey_PerChainAndCache(t *testing.T) {
	var hits int32
	baseKey := "3b36314baa489deeca392467a15af483f4f63178642d3ff124239f088a2ce73b"
	tempoKey := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef0"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/opensouk" {
			http.NotFound(w, r)
			return
		}
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"attestationPubKey": "` + baseKey + `",
			"chains": [
				{"chainId": 84532, "attestationPubKey": "` + baseKey + `"},
				{"chainId": 42431, "attestationPubKey": "` + tempoKey + `"}
			]
		}`))
	}))
	defer srv.Close()

	ctx := context.Background()
	client := srv.Client()

	// Per-chain: matching entry wins.
	got, err := attestationPubKey(ctx, client, srv.URL, 42431)
	if err != nil || got != tempoKey {
		t.Fatalf("chain 42431 pubkey = %q, err %v; want %q", got, err, tempoKey)
	}
	// Repeat same chain -> served from the resolved-key cache, no new HTTP hit.
	if _, err := attestationPubKey(ctx, client, srv.URL, 42431); err != nil {
		t.Fatalf("cached 42431 lookup: %v", err)
	}
	// Base entry (distinct chain -> one more fetch).
	got, err = attestationPubKey(ctx, client, srv.URL, 84532)
	if err != nil || got != baseKey {
		t.Fatalf("chain 84532 pubkey = %q, err %v; want %q", got, err, baseKey)
	}
	if _, err := attestationPubKey(ctx, client, srv.URL, 84532); err != nil {
		t.Fatalf("cached 84532 lookup: %v", err)
	}
	// Two distinct chains => 2 manifest fetches; repeat lookups are cached.
	if h := atomic.LoadInt32(&hits); h != 2 {
		t.Errorf("manifest fetched %d times, want 2 (one per distinct chain, repeats cached)", h)
	}
}

// TestAttestationPubKey_TransientEmptyNotCached is the regression guard for the caching
// bug: a 200 OK manifest with no usable key must NOT be pinned — once the host recovers,
// a retry must succeed without a process restart.
func TestAttestationPubKey_TransientEmptyNotCached(t *testing.T) {
	var serveGood int32
	goodKey := "3b36314baa489deeca392467a15af483f4f63178642d3ff124239f088a2ce73b"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&serveGood) == 0 {
			// Transient: HTTP 200 + valid JSON, but no usable key (top-level and the
			// chain entry are both empty — the case the PR's minimal guard would miss).
			_, _ = w.Write([]byte(`{"attestationPubKey":"","chains":[{"chainId":84532,"attestationPubKey":""}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"attestationPubKey":"` + goodKey + `","chains":[]}`))
	}))
	defer srv.Close()

	ctx := context.Background()
	if _, err := attestationPubKey(ctx, srv.Client(), srv.URL, 84532); err == nil {
		t.Fatal("expected error on a manifest with no usable key, got nil")
	}
	// Host recovers; the retry must now succeed (the bad response was not pinned).
	atomic.StoreInt32(&serveGood, 1)
	got, err := attestationPubKey(ctx, srv.Client(), srv.URL, 84532)
	if err != nil || got != goodKey {
		t.Fatalf("after recovery: got %q, err %v; want %q", got, err, goodKey)
	}
}

func TestAttestationPubKey_UnknownChainFallsBackToTopLevel(t *testing.T) {
	topKey := "3b36314baa489deeca392467a15af483f4f63178642d3ff124239f088a2ce73b"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"attestationPubKey": "` + topKey + `", "chains": []}`))
	}))
	defer srv.Close()

	got, err := attestationPubKey(context.Background(), srv.Client(), srv.URL, 84532)
	if err != nil || got != topKey {
		t.Fatalf("fallback pubkey = %q, err %v; want %q", got, err, topKey)
	}
}
