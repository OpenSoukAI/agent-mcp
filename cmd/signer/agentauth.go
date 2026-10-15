package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
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
//
// Re-signing is not enough on its own, because the timestamp has one-second resolution:
// the same body signed twice in the same second produces the same payload hash and the
// second request is rejected as a replay. That is not a corner case — an authenticated
// GET has an EMPTY body, so two stats reads a few milliseconds apart are byte-identical,
// and a composite retried straight after a failure resends the same JSON. freshTimestampFor
// is what keeps them distinct.

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
func agentAuthSignature(ctx context.Context, body []byte, timestamp int64, key Signer) (string, error) {
	if key == nil {
		return "", fmt.Errorf("no signing key for the authenticated backend call")
	}
	sig, err := key.SignDigest(ctx, common.BytesToHash(accounts.TextHash(agentAuthPayloadHash(body, timestamp))))
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
	key Signer,
) (*http.Request, error) {
	timestamp, err := freshTimestampFor(body)
	if err != nil {
		return nil, err
	}

	sig, err := agentAuthSignature(ctx, body, timestamp, key)
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

// ── Replay-safe timestamps ──────────────────────────────────────────────────────

var (
	signedMu sync.Mutex
	// signedAt maps a payload hash this process has already signed to the second at which
	// it stops being replay-relevant. Bounded by pruning on every call: an entry older than
	// the server's acceptance window can no longer collide with anything.
	signedAt = map[string]int64{}
)

// replayWindowSeconds mirrors the backend's timestampWindow (60s) plus its replaySlack. A
// payload hash older than this is outside every window the server will still accept, so it
// cannot collide and the entry can go.
const replayWindowSeconds = 61

// freshTimestampFor returns a unix second at which this exact body has not already been
// signed by this process.
//
// It steps FORWARD rather than sleeping. The server accepts a timestamp up to 60s ahead, so
// a step costs nothing, whereas waiting for the next second would add up to a second of
// latency to every quick repeat — and quick repeats are the normal case here: retry a
// composite, poll stats twice.
//
// This only de-duplicates within one process. Two processes signing with the same key can
// still collide, and rejecting that is the server's job.
func freshTimestampFor(body []byte) (int64, error) {
	signedMu.Lock()
	defer signedMu.Unlock()

	now := time.Now().Unix()

	for h, expiry := range signedAt {
		if expiry < now {
			delete(signedAt, h)
		}
	}

	for ts := now; ts <= now+replayWindowSeconds; ts++ {
		h := string(agentAuthPayloadHash(body, ts))
		if _, used := signedAt[h]; used {
			continue
		}
		signedAt[h] = ts + replayWindowSeconds
		return ts, nil
	}

	// Unreachable in practice: it needs the identical body signed 62 times inside one second.
	return 0, fmt.Errorf("cannot sign this request without repeating a payload the server would " +
		"reject as a replay — the identical request has been sent too many times in one second")
}
