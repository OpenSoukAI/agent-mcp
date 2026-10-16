package main

import (
	"crypto/ecdsa"
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
