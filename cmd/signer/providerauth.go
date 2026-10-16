package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
