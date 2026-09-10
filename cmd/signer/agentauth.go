package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

// ── AgentAuth: signed REST calls to the backend ─────────────────────────────────
//
// The backend recovers the caller's address from an EIP-191 personal_sign over
// keccak256(body || uint64_be(unix_seconds)), carried in two headers. See
// backend/internal/api/middleware/auth.go.
//
// Two rules are invisible from the signature alone: the timestamp must be within
// ±60 s of SERVER time, and the backend rejects a second request bearing the same
// (signer, payload hash). Together they mean a retry must re-sign — reusing headers
// from a failed attempt is a replay and is rejected. Hence newAuthedRequest stamps
// its own timestamp instead of taking one, so no caller can cache a signed pair.

const (
	agentSignatureHeader = "X-Agent-Signature"
	agentTimestampHeader = "X-Agent-Timestamp"
)

// agentAuthPayloadHash is the message the agent signs. body may be empty: the
// authenticated GETs (e.g. /v1/merchant/:id/stats) sign the timestamp alone.
func agentAuthPayloadHash(body []byte, timestamp int64) []byte {
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(timestamp))
	return crypto.Keccak256(body, tsBuf[:])
}

// agentAuthSignature returns the 65-byte signature as 0x-hex with v in {27, 28}.
func agentAuthSignature(body []byte, timestamp int64, key *ecdsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("no signing key for the authenticated backend call")
	}
	sig, err := crypto.Sign(accounts.TextHash(agentAuthPayloadHash(body, timestamp)), key)
	if err != nil {
		return "", fmt.Errorf("sign agent auth payload: %w", err)
	}
	sig[64] += 27 // personal_sign uses v=27/28; crypto.Sign returns v=0/1
	return "0x" + hex.EncodeToString(sig), nil
}

// newAuthedRequest builds a signed JSON request against the backend.
func newAuthedRequest(
	ctx context.Context,
	method, url string,
	body []byte,
	key *ecdsa.PrivateKey,
) (*http.Request, error) {
	timestamp := time.Now().Unix()
	sig, err := agentAuthSignature(body, timestamp, key)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build %s %s: %w", method, url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(agentSignatureHeader, sig)
	req.Header.Set(agentTimestampHeader, strconv.FormatInt(timestamp, 10))
	return req, nil
}
