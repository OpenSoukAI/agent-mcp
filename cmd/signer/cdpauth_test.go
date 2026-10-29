package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// decodeJWTPart base64url-decodes one '.'-separated JWT segment into dst.
func decodeJWTPart(t *testing.T, part string, dst any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		t.Fatalf("decode JWT part: %v", err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("unmarshal JWT part: %v", err)
	}
}

func TestCDPBearerJWT(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := &cdpAPIKey{id: "organizations/org/apiKeys/key-1", priv: priv}
	now := time.Unix(1700000000, 0)
	uri := "POST api.cdp.coinbase.com/platform/v2/evm/accounts"

	tok, err := key.bearer(uri, now)
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	var header struct {
		Alg   string `json:"alg"`
		Typ   string `json:"typ"`
		Kid   string `json:"kid"`
		Nonce string `json:"nonce"`
	}
	decodeJWTPart(t, parts[0], &header)
	if header.Alg != "EdDSA" {
		t.Errorf("alg = %q, want EdDSA", header.Alg)
	}
	if header.Kid != key.id {
		t.Errorf("kid = %q, want %q", header.Kid, key.id)
	}
	if len(header.Nonce) != 32 {
		t.Errorf("nonce len = %d, want 32 hex chars", len(header.Nonce))
	}
	if _, err := hex.DecodeString(header.Nonce); err != nil {
		t.Errorf("nonce not hex: %v", err)
	}

	var claims struct {
		Sub  string   `json:"sub"`
		Iss  string   `json:"iss"`
		Aud  []string `json:"aud"`
		Nbf  int64    `json:"nbf"`
		Exp  int64    `json:"exp"`
		URIs []string `json:"uris"`
	}
	decodeJWTPart(t, parts[1], &claims)
	if claims.Sub != key.id {
		t.Errorf("sub = %q, want %q", claims.Sub, key.id)
	}
	if claims.Iss != "cdp" {
		t.Errorf("iss = %q, want cdp", claims.Iss)
	}
	if len(claims.Aud) != 1 || claims.Aud[0] != "cdp_service" {
		t.Errorf("aud = %v, want [cdp_service]", claims.Aud)
	}
	if claims.Exp-claims.Nbf != 120 {
		t.Errorf("exp-nbf = %d, want 120", claims.Exp-claims.Nbf)
	}
	if len(claims.URIs) != 1 || claims.URIs[0] != uri {
		t.Errorf("uris = %v, want [%s]", claims.URIs, uri)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		t.Error("ed25519 signature does not verify")
	}
}

func TestCDPWalletJWT(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cred := &p256Credential{priv: priv, pubHex: hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))}
	now := time.Unix(1700000000, 0)
	uri := "POST api.cdp.coinbase.com/platform/v2/evm/accounts/0x.../send"
	body := []byte(`{"amount":"1"}`)

	tok, err := cred.cdpWalletJWT(uri, body, now)
	if err != nil {
		t.Fatalf("cdpWalletJWT: %v", err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	decodeJWTPart(t, parts[0], &header)
	if header.Alg != "ES256" {
		t.Errorf("alg = %q, want ES256", header.Alg)
	}

	var claims struct {
		Iat     int64    `json:"iat"`
		Nbf     int64    `json:"nbf"`
		Jti     string   `json:"jti"`
		URIs    []string `json:"uris"`
		ReqHash string   `json:"reqHash"`
	}
	decodeJWTPart(t, parts[1], &claims)
	wantHash := sha256.Sum256(body)
	if claims.ReqHash != hex.EncodeToString(wantHash[:]) {
		t.Errorf("reqHash = %q, want %q", claims.ReqHash, hex.EncodeToString(wantHash[:]))
	}
	if len(claims.URIs) != 1 || claims.URIs[0] != uri {
		t.Errorf("uris = %v, want [%s]", claims.URIs, uri)
	}
	if claims.Iat != claims.Nbf {
		t.Errorf("iat %d != nbf %d", claims.Iat, claims.Nbf)
	}
	if len(claims.Jti) != 32 {
		t.Errorf("jti len = %d, want 32 hex chars", len(claims.Jti))
	}
	if _, err := hex.DecodeString(claims.Jti); err != nil {
		t.Errorf("jti not hex: %v", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature len = %d, want 64", len(sig))
	}
	signingInput := parts[0] + "." + parts[1]
	h := sha256.Sum256([]byte(signingInput))
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&priv.PublicKey, h[:], r, s) {
		t.Error("ecdsa signature does not verify")
	}
}

func TestCDPBodyIsSortedAndUnescaped(t *testing.T) {
	got, err := cdpBody(map[string]any{"b": "<&>", "a": 1})
	if err != nil {
		t.Fatalf("cdpBody: %v", err)
	}
	want := `{"a":1,"b":"<&>"}`
	if string(got) != want {
		t.Errorf("cdpBody = %q, want %q", got, want)
	}
}

func TestCDPAPIKeyFromEnvRefusals(t *testing.T) {
	validSecret := func() string {
		raw := make([]byte, ed25519.PrivateKeySize)
		if _, err := rand.Read(raw); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}()

	cases := []struct {
		name   string
		id     string
		secret string
	}{
		{"empty id", "", validSecret},
		{"PEM-looking secret", "key-1", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIxyz\n-----END EC PRIVATE KEY-----"},
		{"wrong length secret", "key-1", base64.StdEncoding.EncodeToString(make([]byte, 32))},
		{"non-base64 secret", "key-1", "%%%"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cdpAPIKeyFromEnv(tc.id, tc.secret)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tc.name == "PEM-looking secret" && !strings.Contains(err.Error(), "Ed25519") {
				t.Errorf("error %q does not mention Ed25519", err.Error())
			}
		})
	}
}

func TestCDPWalletSecretRefusesNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cdpWalletSecret(base64.StdEncoding.EncodeToString(der))
	if err == nil {
		t.Fatal("expected error for P-384 key, got nil")
	}
}
