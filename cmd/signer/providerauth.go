package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gowebpki/jcs"
)

// P-256 API credentials for the policy providers. These authenticate requests to Turnkey and
// Privy; they are not wallet keys and cannot sign a transaction or an EIP-712 message. This is
// the one file besides keybackend.go allowed to hold an ecdsa.PrivateKey.

type p256Credential struct {
	priv   *ecdsa.PrivateKey
	pubHex string // compressed, hex
}

// turnkeyCredential parses a Turnkey API key pair: the private scalar and the compressed public
// key, both hex. The public key must belong to the private one.
func turnkeyCredential(privHex, pubHex string) (*p256Credential, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(privHex), "0x"))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("TURNKEY_API_PRIVATE_KEY is not a 32-byte hex P-256 private key")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), raw)
	if err != nil {
		return nil, errors.New("TURNKEY_API_PRIVATE_KEY is not a valid P-256 private key")
	}
	derived := hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))
	if !strings.EqualFold(derived, strings.TrimPrefix(strings.TrimSpace(pubHex), "0x")) {
		return nil, errors.New("TURNKEY_API_PUBLIC_KEY does not belong to TURNKEY_API_PRIVATE_KEY")
	}
	return &p256Credential{priv: priv, pubHex: derived}, nil
}

// turnkeyStamp is the X-Stamp header for body: base64url (no padding) of the stamp JSON, whose
// signature is ECDSA-P256-SHA256 over the exact body bytes, DER, hex.
func (c *p256Credential) turnkeyStamp(body []byte) (string, error) {
	h := sha256.Sum256(body)
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, h[:])
	if err != nil {
		return "", fmt.Errorf("stamp Turnkey request: %w", err)
	}
	st, err := json.Marshal(map[string]string{"publicKey": c.pubHex, "signature": hex.EncodeToString(sig), "scheme": "SIGNATURE_SCHEME_TK_API_P256"})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(st), nil
}

// privyCredential parses a Privy authorization key: "wallet-auth:" + base64 PKCS#8 DER P-256.
func privyCredential(key string) (*p256Credential, error) {
	key = strings.TrimSpace(key)
	b64, ok := strings.CutPrefix(key, "wallet-auth:")
	if !ok {
		return nil, errors.New("PRIVY_AUTHORIZATION_KEY must start with wallet-auth: (copy it whole from the Privy dashboard)")
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, errors.New("PRIVY_AUTHORIZATION_KEY is not base64 after wallet-auth:")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("PRIVY_AUTHORIZATION_KEY is not a PKCS#8 private key")
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("PRIVY_AUTHORIZATION_KEY is not a P-256 key")
	}
	return &p256Credential{priv: priv, pubHex: hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))}, nil
}

// privySignature is the privy-authorization-signature for a request: ECDSA-P256-SHA256 over the
// RFC 8785 canonical form of {version, method, url, body, headers}, DER, base64. It also returns
// the canonical bytes it signed.
func (c *p256Credential) privySignature(method, url string, body []byte, appID string) (string, []byte, error) {
	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", nil, fmt.Errorf("Privy request body is not JSON: %w", err)
	}
	payload, err := json.Marshal(map[string]any{"version": 1, "method": method, "url": url, "body": parsed,
		"headers": map[string]any{"privy-app-id": appID}})
	if err != nil {
		return "", nil, err
	}
	canon, err := jcs.Transform(payload)
	if err != nil {
		return "", nil, fmt.Errorf("canonicalise Privy request: %w", err)
	}
	h := sha256.Sum256(canon)
	sig, err := ecdsa.SignASN1(rand.Reader, c.priv, h[:])
	if err != nil {
		return "", nil, fmt.Errorf("sign Privy request: %w", err)
	}
	return base64.StdEncoding.EncodeToString(sig), canon, nil
}

// spkiB64 is the public key as Privy lists it on a key quorum: base64 of the DER
// SubjectPublicKeyInfo.
func (c *p256Credential) spkiB64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&c.priv.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// cdpAPIKey is a Coinbase CDP Ed25519 API key, used to mint the bearer JWT on every CDP request.
type cdpAPIKey struct {
	id   string
	priv ed25519.PrivateKey
}

// cdpAPIKeyFromEnv parses CDP_API_KEY_ID / CDP_API_KEY_SECRET. The secret is base64 of the raw
// 64-byte Ed25519 private key (seed||public), the form the CDP Portal exports for an Ed25519 API
// key. CDP also offers ECDSA (P-256) API keys exported as PEM, which this adapter does not
// support, so a PEM-looking secret gets a pointed error.
func cdpAPIKeyFromEnv(id, secret string) (*cdpAPIKey, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, errors.New("CDP_API_KEY_ID is empty")
	}
	secret = strings.TrimSpace(secret)
	if strings.Contains(secret, "-----BEGIN") {
		return nil, errors.New("CDP_API_KEY_SECRET is a PEM key; create an Ed25519 API key in the CDP Portal instead")
	}
	raw, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, errors.New("CDP_API_KEY_SECRET is not valid base64")
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("CDP_API_KEY_SECRET must decode to %d bytes (an Ed25519 seed||public key), got %d", ed25519.PrivateKeySize, len(raw))
	}
	return &cdpAPIKey{id: id, priv: ed25519.PrivateKey(raw)}, nil
}

// bearer mints the CDP "Bearer JWT" for one request: header carries the key id and a fresh
// nonce, claims bind the token to this exact URI for 120 seconds.
func (k *cdpAPIKey) bearer(uri string, now time.Time) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate CDP bearer nonce: %w", err)
	}
	header, err := json.Marshal(map[string]any{
		"alg": "EdDSA", "typ": "JWT", "kid": k.id, "nonce": hex.EncodeToString(nonce),
	})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"sub": k.id, "iss": "cdp", "aud": []string{"cdp_service"},
		"nbf": now.Unix(), "exp": now.Unix() + 120, "uris": []string{uri},
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	sig := ed25519.Sign(k.priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// cdpWalletSecret parses CDP_WALLET_SECRET: base64 of a PKCS#8 DER P-256 key, the credential that
// authorizes a CDP Server Wallet to act (reuses the Turnkey/Privy p256Credential type).
func cdpWalletSecret(b64 string) (*p256Credential, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, errors.New("CDP_WALLET_SECRET is not valid base64")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("CDP_WALLET_SECRET is not a PKCS#8 private key")
	}
	priv, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || priv.Curve != elliptic.P256() {
		return nil, errors.New("CDP_WALLET_SECRET is not a P-256 key")
	}
	return &p256Credential{priv: priv, pubHex: hex.EncodeToString(elliptic.MarshalCompressed(elliptic.P256(), priv.X, priv.Y))}, nil
}

// cdpWalletJWT mints the CDP "Wallet JWT" that authorizes one request body: claims bind the
// token to this URI and to reqHash, the sha256 of the exact body bytes, so it cannot be replayed
// against a different request. The ES256 signature is raw r||s (JWS form), not DER.
func (c *p256Credential) cdpWalletJWT(uri string, body []byte, now time.Time) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate CDP wallet JWT jti: %w", err)
	}
	reqHash := sha256.Sum256(body)
	header, err := json.Marshal(map[string]any{"alg": "ES256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Unix(), "nbf": now.Unix(), "jti": hex.EncodeToString(jti),
		"uris": []string{uri}, "reqHash": hex.EncodeToString(reqHash[:]),
	})
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	h := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, c.priv, h[:])
	if err != nil {
		return "", fmt.Errorf("sign CDP wallet JWT: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// cdpBody encodes v the way CDP's reqHash expects: compact JSON, map keys sorted (encoding/json's
// default), HTML characters left unescaped, no trailing newline.
func cdpBody(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
