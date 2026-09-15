package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func keyPair(t *testing.T, seedByte byte) (ed25519.PrivateKey, string) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv, hex.EncodeToString(priv.Public().(ed25519.PublicKey))
}

// REF-322: the token's kid selects the public key; a token without kid is the launch key (0).
func TestVerifyAndDecodeToken_SelectsKeyByKid(t *testing.T) {
	priv0, pub0 := keyPair(t, 1)
	priv1, pub1 := keyPair(t, 2)
	keys := map[uint8]string{0: pub0, 1: pub1}

	legacy := validTestToken() // no kid field set → 0
	if _, err := verifyAndDecodeTokenWithKeys(signTestToken(t, priv0, legacy), keys); err != nil {
		t.Fatalf("kid-0 (absent) token under the launch key: %v", err)
	}

	rotated := validTestToken()
	rotated.KeyID = 1
	tok, err := verifyAndDecodeTokenWithKeys(signTestToken(t, priv1, rotated), keys)
	if err != nil {
		t.Fatalf("kid-1 token under key 1: %v", err)
	}
	if tok.KeyID != 1 {
		t.Fatalf("decoded kid = %d, want 1", tok.KeyID)
	}

	// kid says 1 but key 0 signed: the kid only chooses which key must have signed.
	if _, err := verifyAndDecodeTokenWithKeys(signTestToken(t, priv0, rotated), keys); err == nil || !strings.Contains(err.Error(), "signature invalid") {
		t.Fatalf("kid-1 payload signed by key 0 must fail the signature check, got %v", err)
	}
	// Unknown kid: its own error, so the operator hears "publish/rotate", not "forged".
	unknown := validTestToken()
	unknown.KeyID = 9
	if _, err := verifyAndDecodeTokenWithKeys(signTestToken(t, priv1, unknown), keys); err == nil || !strings.Contains(err.Error(), "key id 9") {
		t.Fatalf("unknown kid must be rejected by name, got %v", err)
	}
}

// The single-key entry point keeps working for callers and tests that predate kid: it is the
// key set {0: pubKeyHex}.
func TestVerifyAndDecodeToken_SingleKeyIsKid0(t *testing.T) {
	priv, pub := keyPair(t, 3)
	if _, err := verifyAndDecodeToken(signTestToken(t, priv, validTestToken()), pub); err != nil {
		t.Fatal(err)
	}
	rotated := validTestToken()
	rotated.KeyID = 1
	if _, err := verifyAndDecodeToken(signTestToken(t, priv, rotated), pub); err == nil {
		t.Fatal("single-key verifier must not accept a kid-1 token")
	}
}

// attestationPubKeys reads the manifest's attestationPubKeys (per chain first), falls back to
// the legacy attestationPubKey as kid 0 for a backend that predates REF-322, and refetches
// once when asked for a kid it has not cached — so a rotation needs no signer restart.
func TestAttestationPubKeys_KeySetFallbackAndRefetch(t *testing.T) {
	pubKeyCacheMu.Lock()
	pubKeyCache = map[string]string{}
	pubKeySetCache = map[string]map[uint8]string{}
	pubKeyCacheMu.Unlock()

	var hits atomic.Int32
	var serveRotated atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		m := map[string]any{"attestationPubKey": "aa"}
		if serveRotated.Load() {
			m["attestationPubKeys"] = map[string]string{"0": "aa", "1": "bb"}
			m["chains"] = []map[string]any{{"chainId": 84532, "attestationPubKey": "cc", "attestationPubKeys": map[string]string{"0": "cc", "1": "dd"}}}
		}
		_ = json.NewEncoder(w).Encode(m)
	}))
	defer srv.Close()
	ctx := context.Background()

	// Legacy backend: only attestationPubKey → treated as {0: key}.
	keys, err := attestationPubKeys(ctx, srv.Client(), srv.URL, 84532, 0)
	if err != nil {
		t.Fatal(err)
	}
	if keys[0] != "aa" || len(keys) != 1 {
		t.Fatalf("legacy fallback = %v, want {0: aa}", keys)
	}
	// Cached: a second call for a known kid does not refetch.
	if _, err := attestationPubKeys(ctx, srv.Client(), srv.URL, 84532, 0); err != nil || hits.Load() != 1 {
		t.Fatalf("known kid should be served from cache (hits=%d, err=%v)", hits.Load(), err)
	}
	// Backend rotates; the signer asks for kid 1 → refetch once, per-chain set preferred.
	serveRotated.Store(true)
	keys, err = attestationPubKeys(ctx, srv.Client(), srv.URL, 84532, 1)
	if err != nil {
		t.Fatal(err)
	}
	if keys[1] != "dd" || keys[0] != "cc" || hits.Load() != 2 {
		t.Fatalf("after rotation keys=%v hits=%d, want per-chain {0:cc,1:dd} after exactly one refetch", keys, hits.Load())
	}
	// Still-unknown kid after a refetch: the set is returned as is; the verifier rejects.
	if _, err := attestationPubKeys(ctx, srv.Client(), srv.URL, 84532, 7); err != nil || hits.Load() != 3 {
		t.Fatalf("unknown kid should refetch once more then return the set (hits=%d, err=%v)", hits.Load(), err)
	}
}
