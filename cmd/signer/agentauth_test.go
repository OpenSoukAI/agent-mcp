package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
)

// Golden AgentAuth fixture, shared with the backend (REF-251).
//
// These bytes are IDENTICAL to backend/internal/api/middleware/agentauth_golden_internal_test.go's
// fixture, on purpose, and were produced by a third implementation (`cast wallet sign`) so
// neither Go side is its own oracle. This test asserts the signer PRODUCES these bytes; the
// backend's asserts recoverAddress ACCEPTS them. A one-sided change to the scheme breaks the
// other repo's build.
//
// Every authenticated merchant tool signs this way, so a silent drift locks agents out of
// writing at all. Regenerating the fixture would hide exactly that.
const (
	goldenAuthKey     = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" // anvil account 0
	goldenAuthKeyAddr = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	goldenAuthTS      = int64(1700000000)

	goldenAuthBody = `{"merchant_id":4,"display_name":"Golden Shop"}`
	goldenAuthHash = "864bc1600be666b00e0b264f722339cc71a106ee0355eb4a674b628981cd14b0"
	goldenAuthSig  = "0xcf39fda2378b3d83bcd2ffd17d0672902eea37ccfa51ea1eab8c872c919bbe396b94e910039abb2632b4e367f101fa1cdf97768789ccb5b6e48e7b154257c10b1b"

	// Empty-body case: GET /v1/merchant/:id/stats is authenticated and carries no body.
	goldenAuthEmptyHash = "e1864e0a221adeddc3b6212f67ce6df72c9daa647472d35f8705a4fc53a2d35a"
	goldenAuthEmptySig  = "0x6a6a99743df56fc2db7326677c42df28a5a48d3a34fe32027419a02ee218cfe002fb781f0688a184f0cadd6f80054a983a1dc31544c0d93a0495febba89a48a91b"
)

func goldenKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := crypto.HexToECDSA(goldenAuthKey)
	if err != nil {
		t.Fatalf("HexToECDSA: %v", err)
	}
	return k
}

func TestAgentAuthSignature_GoldenVectors(t *testing.T) {
	key := goldenKey(t)

	cases := []struct {
		name     string
		body     []byte
		wantHash string
		wantSig  string
	}{
		{"body", []byte(goldenAuthBody), goldenAuthHash, goldenAuthSig},
		{"empty body", nil, goldenAuthEmptyHash, goldenAuthEmptySig},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(agentAuthPayloadHash(tc.body, goldenAuthTS)); got != tc.wantHash {
				t.Errorf("payloadHash = %s, want %s", got, tc.wantHash)
			}

			sig, err := agentAuthSignature(tc.body, goldenAuthTS, key)
			if err != nil {
				t.Fatalf("agentAuthSignature: %v", err)
			}
			if sig != tc.wantSig {
				t.Errorf("signature = %s\n            want %s\n\nThe backend will recover a "+
					"different address (or none) from this. Do not regenerate the fixture.",
					sig, tc.wantSig)
			}
		})
	}
}

// TestAgentAuthPayloadHash_TimestampIsBigEndian pins the timestamp's byte order. Both
// endiannesses yield a well-formed signature over a well-formed hash, so a swap is
// invisible to every check except this one — it surfaces only as the wrong recovered signer.
func TestAgentAuthPayloadHash_TimestampIsBigEndian(t *testing.T) {
	var want [8]byte
	binary.BigEndian.PutUint64(want[:], uint64(goldenAuthTS))
	if hex.EncodeToString(want[:]) != "000000006553f100" {
		t.Fatalf("fixture timestamp is not the one the golden bytes were made with")
	}

	const reversed = int64(0x00f1536500000000)
	if got := hex.EncodeToString(agentAuthPayloadHash([]byte(goldenAuthBody), reversed)); got == goldenAuthHash {
		t.Fatal("byte-reversed timestamp produced the golden hash — the timestamp is being " +
			"packed little-endian")
	}
}

// TestAgentAuthSignature_TimestampIsSigned catches a hash that ignores the timestamp
// entirely. Such a signature would still verify, but it would be replayable forever.
func TestAgentAuthSignature_TimestampIsSigned(t *testing.T) {
	key := goldenKey(t)

	first, err := agentAuthSignature([]byte(goldenAuthBody), goldenAuthTS, key)
	if err != nil {
		t.Fatalf("agentAuthSignature: %v", err)
	}
	second, err := agentAuthSignature([]byte(goldenAuthBody), goldenAuthTS+1, key)
	if err != nil {
		t.Fatalf("agentAuthSignature: %v", err)
	}
	if first == second {
		t.Fatal("same signature one second apart — the timestamp is not inside the signed " +
			"payload, so any captured request replays forever")
	}
}

func TestAgentAuthSignature_NoKey(t *testing.T) {
	if _, err := agentAuthSignature([]byte(goldenAuthBody), goldenAuthTS, nil); err == nil {
		t.Fatal("want an error when no signing key is configured, got nil")
	}
}

// TestNewAuthedRequest_HeadersAreRecoverable checks the plumbing the golden vectors cannot:
// that the headers are named what the backend reads, that the timestamp header matches the
// one actually signed, and that the body survives for the transport to send.
//
// recoverAgentAuth below mirrors the backend's recoverAddress, so it is not an independent
// oracle for the SCHEME — the golden vectors are. It is an oracle for the wiring.
func TestNewAuthedRequest_HeadersAreRecoverable(t *testing.T) {
	key := goldenKey(t)
	before := time.Now().Unix()

	req, err := newAuthedRequest(context.Background(), http.MethodPost,
		"http://localhost:8080/v1/merchant/profile", []byte(goldenAuthBody), key)
	if err != nil {
		t.Fatalf("newAuthedRequest: %v", err)
	}
	after := time.Now().Unix()

	if ct := req.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	tsStr := req.Header.Get(agentTimestampHeader)
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		t.Fatalf("%s = %q: %v", agentTimestampHeader, tsStr, err)
	}
	if ts < before || ts > after {
		t.Errorf("%s = %d, want within [%d, %d] — a stale timestamp burns the ±60s window",
			agentTimestampHeader, ts, before, after)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	if string(body) != goldenAuthBody {
		t.Fatalf("request body = %q, want %q", body, goldenAuthBody)
	}

	addr, err := recoverAgentAuth(body, ts, req.Header.Get(agentSignatureHeader))
	if err != nil {
		t.Fatalf("recover from headers: %v", err)
	}
	if addr != goldenAuthKeyAddr {
		t.Errorf("recovered %s, want %s — the signed payload does not match the sent request",
			addr, goldenAuthKeyAddr)
	}
}

// TestNewAuthedRequest_WireHeaderNames pins the header names as LITERALS. Every other test
// reads them back through the same constants, so a rename there would be invisible on both
// sides while the backend, which hardcodes these two strings, silently 401s.
func TestNewAuthedRequest_WireHeaderNames(t *testing.T) {
	req, err := newAuthedRequest(context.Background(), http.MethodPost,
		"http://localhost:8080/v1/merchant/profile", []byte(goldenAuthBody), goldenKey(t))
	if err != nil {
		t.Fatalf("newAuthedRequest: %v", err)
	}

	sig := req.Header.Get("X-Agent-Signature")
	if len(sig) != 132 || !strings.HasPrefix(sig, "0x") {
		t.Errorf("X-Agent-Signature = %q, want a 0x-prefixed 65-byte signature", sig)
	}
	if ts := req.Header.Get("X-Agent-Timestamp"); ts == "" || strings.HasPrefix(ts, "0x") {
		t.Errorf("X-Agent-Timestamp = %q, want decimal unix seconds", ts)
	}
}

func TestNewAuthedRequest_EmptyBodyIsSigned(t *testing.T) {
	key := goldenKey(t)

	req, err := newAuthedRequest(context.Background(), http.MethodGet,
		"http://localhost:8080/v1/merchant/4/stats", nil, key)
	if err != nil {
		t.Fatalf("newAuthedRequest: %v", err)
	}

	ts, err := strconv.ParseInt(req.Header.Get(agentTimestampHeader), 10, 64)
	if err != nil {
		t.Fatalf("parse timestamp header: %v", err)
	}
	addr, err := recoverAgentAuth(nil, ts, req.Header.Get(agentSignatureHeader))
	if err != nil {
		t.Fatalf("recover from headers: %v", err)
	}
	if addr != goldenAuthKeyAddr {
		t.Errorf("recovered %s, want %s", addr, goldenAuthKeyAddr)
	}
}

// recoverAgentAuth mirrors backend recoverAddress: the v normalisation, the payload hash,
// and the EIP-191 prefix.
func recoverAgentAuth(body []byte, timestamp int64, sigHex string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(sigHex, "0x"))
	if err != nil {
		return "", err
	}
	if len(raw) != 65 {
		return "", fmt.Errorf("signature length %d (want 65)", len(raw))
	}
	sig := make([]byte, 65)
	copy(sig, raw)
	if sig[64] >= 27 {
		sig[64] -= 27
	}

	pub, err := crypto.SigToPub(accounts.TextHash(agentAuthPayloadHash(body, timestamp)), sig)
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(*pub).Hex(), nil
}
