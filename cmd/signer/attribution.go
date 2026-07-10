package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/common"
)

// attributionTokenVersion is the only self-contained token version this signer
// decodes at the edge (v4, REF-139: rank-derived multiplier removed, computed live
// at settlement). Mirrors backend internal/signing.tokenVersion.
const attributionTokenVersion = 4

// ed25519SignatureSize is the trailing signature length in the signed token blob.
const ed25519SignatureSize = ed25519.SignatureSize // 64 bytes

// maxTokenLen bounds the base64url token segment, mirroring backend
// reflink.maxTokenLen so any link the backend can mint we can parse back.
const maxTokenLen = 12288

// sentinelBuyerAgentID is the agent-less buyer marker: type(uint256).max, matching
// on-chain ProtocolConstants.SENTINEL_BUYER (SplitRouter/SplitRouterMPP). A buyer
// paying with only a funded wallet (no ERC-8004 identity) sends this as buyerAgentId;
// route() skips the ownerOf bind for it and the paying wallet is captured for the
// deferred identity bind (REF-134 decision 4 / contract track C-3).
var sentinelBuyerAgentID = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1)).String()

// buyerAgentIDOrSentinel maps the tool's optional agent_id to the value sent as
// buyerAgentId in the x402 payload: a non-empty id passes through unchanged; an empty
// id means agent-less (no ERC-8004 identity yet), so the sentinel is used (REF-134).
func buyerAgentIDOrSentinel(agentID string) string {
	if id := strings.TrimSpace(agentID); id != "" {
		return id
	}
	return sentinelBuyerAgentID
}

// decodedAttributionToken is the subset of the self-contained attribution token the
// edge payment flow reads. The token is base64url(payload || 64-byte Ed25519 sig),
// where payload is this deterministic JSON. Field JSON tags MUST match the backend
// (internal/signing.tokenJSON, v4) exactly — the signature is over those bytes.
type decodedAttributionToken struct {
	Version                 uint8  `json:"v"`
	ReviewerAgentID         string `json:"reviewerAgentId"`
	ReviewID                string `json:"reviewId"`
	MerchantID              string `json:"merchantId"`
	ProductID               string `json:"productId"`
	LockedCommissionBps     uint16 `json:"lockedCommissionBps"`     // informational; commission is live at settle
	CashbackOfCommissionBps uint16 `json:"cashbackOfCommissionBps"` // frozen share-of-commission ratio (<=4000)
	ProductType             uint8  `json:"productType"`
	IssuedAt                int64  `json:"issuedAt"`
	ChainID                 int64  `json:"chainId"`
	SplitRouter             string `json:"splitRouter"`
	MerchantEndpoint        string `json:"merchantEndpoint"`
	SetupURL                string `json:"setupUrl"`
}

// verifyAndDecodeToken decodes the base64url attribution token, verifies its trailing
// Ed25519 signature against pubKeyHex, and unmarshals the v4 payload. This is the edge
// replacement for the backend /r/<token> resolution round-trip: everything the buyer
// needs to pay (merchant endpoint, settlement router, chain, cashback ratio) is read
// straight from the signed link. Mirrors backend signing.Verify + Unmarshal.
func verifyAndDecodeToken(rawToken, pubKeyHex string) (decodedAttributionToken, error) {
	if len(rawToken) > maxTokenLen {
		return decodedAttributionToken{}, fmt.Errorf("attribution token too long (%d chars)", len(rawToken))
	}
	signed, err := base64.RawURLEncoding.DecodeString(rawToken)
	if err != nil {
		return decodedAttributionToken{}, fmt.Errorf("decode attribution token base64url: %w", err)
	}
	if len(signed) <= ed25519SignatureSize {
		return decodedAttributionToken{}, fmt.Errorf("attribution token blob too small (%d bytes, want > %d)", len(signed), ed25519SignatureSize)
	}
	pub, err := parseEd25519PubKeyHex(pubKeyHex)
	if err != nil {
		return decodedAttributionToken{}, err
	}

	payload := signed[:len(signed)-ed25519SignatureSize]
	sig := signed[len(signed)-ed25519SignatureSize:]
	if !ed25519.Verify(pub, payload, sig) {
		return decodedAttributionToken{}, fmt.Errorf("attribution token signature invalid — not signed by the protocol attestation key")
	}

	var tok decodedAttributionToken
	if err := json.Unmarshal(payload, &tok); err != nil {
		return decodedAttributionToken{}, fmt.Errorf("decode attribution token payload: %w", err)
	}
	if tok.Version != attributionTokenVersion {
		return decodedAttributionToken{}, fmt.Errorf("unsupported attribution token version %d (want %d)", tok.Version, attributionTokenVersion)
	}
	if tok.MerchantEndpoint == "" {
		return decodedAttributionToken{}, fmt.Errorf("attribution token missing merchantEndpoint")
	}
	if !common.IsHexAddress(tok.SplitRouter) {
		return decodedAttributionToken{}, fmt.Errorf("attribution token has invalid splitRouter %q", tok.SplitRouter)
	}
	return tok, nil
}

// parseEd25519PubKeyHex decodes a hex Ed25519 public key (with or without 0x prefix),
// matching the format the well-known manifest publishes (signing.PublicKeyHex).
func parseEd25519PubKeyHex(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(h, "0x"))
	if err != nil {
		return nil, fmt.Errorf("decode attestation pubkey hex: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("attestation pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}

// splitRefPath splits the path portion after "/r/" into an optional chain segment and
// the base64url token. Base mints the bare <base>/r/<token>; non-Base rails mint the
// chain-qualified <base>/r/<chainID>/<token> (REF-90). The token is always the last
// segment — it is BOTH decoded locally and attached verbatim to the x402 payload.
func splitRefPath(afterR string) (chainSeg, token string, err error) {
	segs := strings.Split(strings.Trim(afterR, "/"), "/")
	switch {
	case len(segs) == 1 && segs[0] != "":
		return "", segs[0], nil
	case len(segs) == 2 && segs[0] != "" && segs[1] != "":
		return segs[0], segs[1], nil
	default:
		return "", "", fmt.Errorf("malformed ref link path %q", afterR)
	}
}

// wellKnownManifest is the subset of GET /.well-known/referrer-agent this signer reads.
// Attestation keys are per-chain (reflink signers differ per rail), so it prefers the
// matching chains[] entry and falls back to the top-level (Base default) key.
type wellKnownManifest struct {
	AttestationPubKey string `json:"attestationPubKey"`
	Chains            []struct {
		ChainID           int64  `json:"chainId"`
		AttestationPubKey string `json:"attestationPubKey"`
	} `json:"chains"`
}

// pubKeyCache memoises the RESOLVED attestation pubkey per (apiBase, chainID). Only a
// non-empty resolved key is ever stored, so a manifest transiently served with a
// missing/empty key is never pinned for the process lifetime — the next call re-fetches
// and retries. Keyed per chain, so a manifest valid for Base but missing another rail's
// key can't poison that rail's lookup.
var (
	pubKeyCacheMu sync.Mutex
	pubKeyCache   = map[string]string{} // apiBase + "|" + chainID -> pubkey hex
)

// attestationPubKey returns the Ed25519 attestation pubkey (hex) for chainID, fetching
// the well-known manifest per apiBase and caching the resolved key. chainID MUST be the
// caller's trusted configured chain (not the token's self-claimed chainId) so key
// selection can't be steered by an unverified token. Keys are per-chain, so it prefers
// the matching chains[] entry and falls back to the top-level (Base default) key.
func attestationPubKey(ctx context.Context, httpClient *http.Client, apiBase string, chainID int64) (string, error) {
	apiBase = strings.TrimRight(apiBase, "/")
	cacheKey := apiBase + "|" + strconv.FormatInt(chainID, 10)

	pubKeyCacheMu.Lock()
	if k, ok := pubKeyCache[cacheKey]; ok {
		pubKeyCacheMu.Unlock()
		return k, nil
	}
	pubKeyCacheMu.Unlock()

	man, err := fetchManifest(ctx, httpClient, apiBase)
	if err != nil {
		return "", err
	}

	pk := man.AttestationPubKey
	for _, c := range man.Chains {
		if c.ChainID == chainID && c.AttestationPubKey != "" {
			pk = c.AttestationPubKey
			break
		}
	}
	if pk == "" {
		// Do NOT cache: a transient empty/malformed manifest must not be pinned so that
		// lookups keep failing after the host is fixed, until this process restarts.
		return "", fmt.Errorf("well-known manifest at %s exposes no attestationPubKey for chain %d", apiBase, chainID)
	}

	pubKeyCacheMu.Lock()
	pubKeyCache[cacheKey] = pk
	pubKeyCacheMu.Unlock()
	return pk, nil
}

// fetchManifest GETs and parses the well-known manifest. It intentionally does NOT
// cache — caching is the caller's job, keyed by the resolved key, so a response with no
// usable key is never memoised.
func fetchManifest(ctx context.Context, httpClient *http.Client, apiBase string) (wellKnownManifest, error) {
	url := strings.TrimRight(apiBase, "/") + "/.well-known/referrer-agent"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return wellKnownManifest{}, fmt.Errorf("build well-known request: %w", err)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return wellKnownManifest{}, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return wellKnownManifest{}, fmt.Errorf("fetch %s: HTTP %d: %s", url, resp.StatusCode, body)
	}
	var m wellKnownManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return wellKnownManifest{}, fmt.Errorf("parse well-known manifest from %s: %w", url, err)
	}
	return m, nil
}
