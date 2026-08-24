# REF-174 — `sign_telegram_link_commitment` (referrer-signer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `sign_telegram_link_commitment` MCP tool to the referrer-signer (`agent-mcp`) so an agent can produce the `agent_sig` that backend `link_telegram` step 2 requires — unblocking the agent-initiated (MCP) Telegram-link flow end to end.

**Architecture:** The signer already exposes 5 `sign_*` commitment tools. `link_telegram` on the backend added a **dedicated** `TelegramLinkCommitment` EIP-712 type; the signer has no matching signer. This ticket adds that signer as a byte-for-byte mirror of the existing `sign_cashback_rate_commitment` tool, **minus** the `uint16 cashbackOfCommissionBps` field. The signer defines its own EIP-712 constants (it does not import the backend `signing` package); the domain (name/version/chainId/verifyingContract) is read verbatim from the commitment payload the agent passes in.

**Tech Stack:** Go, `github.com/ethereum/go-ethereum` (`crypto`, `accounts/abi`, `common`), `github.com/modelcontextprotocol/go-sdk/mcp` (alias `sdkmcp`). Module `github.com/Ref-Agent/agent-mcp`, all signer code under `cmd/signer/` (`package main`).

## Global Constraints

- **Repo/branch:** `agent-mcp` module. Its default/integration branch is **`main`** (no `dev`). Branch from `main`; **confirm the PR target is `main`** before opening the PR (unlike backend, which targets `dev`).
- **Signer owns its own EIP-712 constants** — no import of `github.com/Ref-Agent/backend`. The digest reads `Domain.{Name,Version,ChainID,VerifyingContract}` **verbatim** from the payload the agent passes (which is backend `link_telegram` step-1 output). A `telegramLinkDomainName` const is added for documentation/parity only and is intentionally unreferenced (mirrors the existing unused `cashbackRateDomainName`).
- **PARITY IS LOAD-BEARING — must match backend `internal/signing/telegram_link_commitment.go` char-for-char:**
  - Type string (verbatim): `TelegramLinkCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)`
  - Struct ABI-encode order/types: `bytes32(typehash), uint256(agentId), bytes32(nonce), uint256(expiry)`
  - Digest: `keccak256(0x19 0x01 ‖ domainSeparator ‖ structHash)`, `domainSeparator = keccak256(abi.encode(domainTypehash, keccak(name), keccak(version), chainId(uint256), verifyingContract(address)))`.
  - Message field encodings: `agentId` decimal string → `big.Int`; `nonce` `0x`+32-byte hex → `[32]byte`; `expiry` decimal string → `big.Int`.
- **Signature:** `crypto.Sign(digest, key)` then `sig[64] += 27` (OZ ECDSA needs v=27/28); return `"0x"+hex`. 65 bytes total.
- **Key lookup:** `signerKeys.KeyFor(agentID)` — the agent's on-chain **owner** key (backend recover checks `signer == OwnerOf(agentId)`). Provided via `AGENT_KEYS` / `AGENT_PRIVATE_KEY`.
- **Mirror `sign_cashback_rate_commitment` exactly, minus the `uint16 cashbackOfCommissionBps` field** (type string, struct pack args, and message struct).
- Full `go test ./...` green in `agent-mcp` before commit.

## File Structure

- **Create** `cmd/signer/telegram_link.go` — the EIP-712 type string const + typehash, doc-only domain-name const, `signTelegramLinkInput` / `telegramLinkCommitmentPayload` / `telegramLinkCommitmentMessage` structs, `computeTelegramLinkDigest`, `handleSignTelegramLink`. (Follows the dedicated-file pattern of `open_session.go` / `charge_commitment.go`; reuses `package main` globals `domainTypehash`, `abiBytes32`, `abiUint256`, `abiAddress`, `commitmentDomain`, `signOutput`, `hexToBytes32`, `signerKeys`.)
- **Modify** `cmd/signer/main.go` — one `sdkmcp.AddTool(...)` registration in `main()`, immediately after the `sign_cashback_rate_commitment` registration (currently ~`main.go:1038`).
- **Create** `cmd/signer/telegram_link_test.go` — round-trip sign/recover test + type-string pin test.

---

### Task 1: `sign_telegram_link_commitment` tool

**Files:**
- Create: `cmd/signer/telegram_link.go`
- Create: `cmd/signer/telegram_link_test.go`
- Modify: `cmd/signer/main.go` (add one `AddTool` after the cashback registration ~`:1038`)

**Interfaces:**
- Consumes (existing `package main` symbols, do not redeclare): `commitmentDomain` (main.go:88), `signOutput` (main.go:120), `domainTypehash`/`abiBytes32`/`abiUint256`/`abiAddress` (main.go:37-52), `hexToBytes32` (main.go:194), `signerKeys` + `signerKeys.KeyFor` (main.go:253).
- Produces: `handleSignTelegramLink(context.Context, *sdkmcp.CallToolRequest, signTelegramLinkInput) (*sdkmcp.CallToolResult, signOutput, error)`; the `sign_telegram_link_commitment` tool.

- [ ] **Step 1: Write the failing tests**

Create `cmd/signer/telegram_link_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// fixedTelegramPayload builds a representative step-1 commitment payload.
func fixedTelegramPayload() telegramLinkCommitmentPayload {
	return telegramLinkCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerTelegramLink",
			Version:           "1",
			ChainID:           84532, // Base Sepolia
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: telegramLinkCommitmentMessage{
			AgentID: "7",
			Nonce:   "0x" + strings.Repeat("ab", 32), // 32 bytes
			Expiry:  "1893456000",
		},
	}
}

// TestTelegramLinkTypeString_MatchesBackend pins the EIP-712 type string byte-for-byte
// to the backend (internal/signing/telegram_link_commitment.go). A drift here would make
// every signature this tool produces fail backend verification.
func TestTelegramLinkTypeString_MatchesBackend(t *testing.T) {
	const want = "TelegramLinkCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"
	if telegramLinkCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", telegramLinkCommitmentTypeString, want)
	}
}

// TestSignTelegramLink_RoundTrip signs a commitment and recovers the signer from the
// digest, proving the produced 65-byte sig is valid over computeTelegramLinkDigest and
// that the v-byte is normalized to 27/28.
func TestSignTelegramLink_RoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)

	// Load the key for agent "7" via the real keystore path.
	ks, err := parseKeystore("7:0x"+hexKey(key), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	p := fixedTelegramPayload()
	_, out, err := handleSignTelegramLink(nil, nil, signTelegramLinkInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignTelegramLink: %v", err)
	}

	digest, err := computeTelegramLinkDigest(p)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := hexTo65(out.Signature)
	if err != nil {
		t.Fatalf("decode sig: %v", err)
	}
	// Recover: crypto.SigToPub expects v=0/1, tool emits v=27/28.
	recSig := make([]byte, 65)
	copy(recSig, sig)
	recSig[64] -= 27
	pub, err := crypto.SigToPub(digest, recSig)
	if err != nil {
		t.Fatalf("SigToPub: %v", err)
	}
	if got := crypto.PubkeyToAddress(*pub); got != want {
		t.Fatalf("recovered %s, want %s", got, want)
	}
}

// small test helpers (kept local to avoid touching production code)
func hexKey(k interface{ D() any }) string { return "" } // replaced below
```

> **Implementer note on the two helpers:** `parseKeystore` expects `"<agentId>:0x<privhex>"`. Get the private-key hex with `hex.EncodeToString(crypto.FromECDSA(key))` (add `encoding/hex` + drop the stub `hexKey`; inline it: `"7:0x"+hex.EncodeToString(crypto.FromECDSA(key))`). For `hexTo65`, decode `out.Signature` (a `0x`+130-hex string) with `hex.DecodeString(strings.TrimPrefix(out.Signature,"0x"))` and assert `len==65`. Write these inline rather than as stubs — the stub above is only a placeholder to make the intent explicit; replace it. If `parseKeystore`'s exact `AGENT_KEYS` format differs, read `cmd/signer/main.go:206-250` and match it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'TestTelegramLink|TestSignTelegramLink' -v`
Expected: FAIL to compile — `telegramLinkCommitmentTypeString`, `telegramLinkCommitmentPayload`, `signTelegramLinkInput`, `computeTelegramLinkDigest`, `handleSignTelegramLink` undefined.

- [ ] **Step 3: Implement `cmd/signer/telegram_link.go`**

```go
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── TelegramLinkCommitment EIP-712 (must match backend signing/telegram_link_commitment.go exactly) ──
// Dedicated type + domain name so a telegram-link authorization can never be replayed as any other
// commitment. Mirrors CashbackRateCommitment field-for-field, MINUS the uint16 cashbackOfCommissionBps.
const telegramLinkCommitmentTypeString = "TelegramLinkCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"

var telegramLinkCommitmentTypehash = crypto.Keccak256Hash([]byte(telegramLinkCommitmentTypeString))

// telegramLinkDomainName documents the expected domain name (backend: "ReferrerTelegramLink").
// Like cashbackRateDomainName it is documentation-only and intentionally unreferenced — the digest
// reads the domain verbatim from the commitment payload the agent passes in.
const telegramLinkDomainName = "ReferrerTelegramLink"

type telegramLinkCommitmentMessage struct {
	AgentID string `json:"agentId"`
	Nonce   string `json:"nonce"`
	Expiry  string `json:"expiry"`
}

type telegramLinkCommitmentPayload struct {
	// Types and PrimaryType are part of the EIP-712 envelope — accepted but ignored.
	Types       map[string]any                `json:"types,omitempty"`
	PrimaryType string                        `json:"primaryType,omitempty"`
	Domain      commitmentDomain              `json:"domain"`
	Message     telegramLinkCommitmentMessage `json:"message"`
}

type signTelegramLinkInput struct {
	Commitment telegramLinkCommitmentPayload `json:"commitment"`
}

func computeTelegramLinkDigest(p telegramLinkCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiAddress},
	}.Pack(
		domainTypehash,
		crypto.Keccak256Hash([]byte(p.Domain.Name)),
		crypto.Keccak256Hash([]byte(p.Domain.Version)),
		chainID,
		contractAddr,
	)
	if err != nil {
		return nil, fmt.Errorf("pack domain: %w", err)
	}
	domainSeparator := crypto.Keccak256Hash(domainPacked)

	agentID, ok := new(big.Int).SetString(p.Message.AgentID, 10)
	if !ok {
		return nil, fmt.Errorf("invalid agentId: %q", p.Message.AgentID)
	}
	nonce, err := hexToBytes32(p.Message.Nonce)
	if err != nil {
		return nil, fmt.Errorf("invalid nonce: %w", err)
	}
	expiry, ok := new(big.Int).SetString(p.Message.Expiry, 10)
	if !ok {
		return nil, fmt.Errorf("invalid expiry: %q", p.Message.Expiry)
	}

	structPacked, err := abi.Arguments{
		{Type: abiBytes32},
		{Type: abiUint256},
		{Type: abiBytes32},
		{Type: abiUint256},
	}.Pack(
		telegramLinkCommitmentTypehash,
		agentID, nonce, expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignTelegramLink(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signTelegramLinkInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}

	digest, err := computeTelegramLinkDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}

	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27 // OZ ECDSA requires v=27/28; crypto.Sign returns v=0/1

	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}
```

> If `go vet`/compiler flags `telegramLinkDomainName` as unused, it will NOT — Go permits unused package-level consts/vars (the sibling `cashbackRateDomainName` is likewise unused). If `hex` ends up unused after your final handler, remove the import; here it is used by `handleSignTelegramLink`.

- [ ] **Step 4: Register the tool in `main.go`**

In `cmd/signer/main.go`, immediately after the `sign_cashback_rate_commitment` `AddTool` (~`:1038`), add:

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_telegram_link_commitment",
		Description: "Sign an EIP-712 TelegramLinkCommitment using the agent's owner private key. " +
			"Call this between link_telegram step 1 and step 2: pass the 'commitment' object from " +
			"link_telegram step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in link_telegram step 2 (with the same nonce and expiry).",
	}, handleSignTelegramLink)
```

- [ ] **Step 5: Run tests + full suite**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'TestTelegramLink|TestSignTelegramLink' -v && go build ./... && go vet ./... && go test ./...`
Expected: the two new tests PASS; full suite green.

- [ ] **Step 6: Commit**

```bash
cd agent-mcp && go test ./... && \
git add cmd/signer/telegram_link.go cmd/signer/telegram_link_test.go cmd/signer/main.go && \
git commit -m "feat(signer): sign_telegram_link_commitment tool (REF-174)"
```
(End the commit body with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.)

---

## Self-Review

**Spec coverage (REF-174):**
- New `sign_telegram_link_commitment` tool → Task 1 ✓
- Mirrors `sign_cashback_rate_commitment` minus `uint16 bps` → type string, struct pack (`bytes32,uint256,bytes32,uint256`), message struct all drop the bps field ✓
- Matches backend `TelegramLinkCommitment` (domain `ReferrerTelegramLink`, type string, encode order) → Global Constraints + type-string pin test + review gate ✓
- Signs with the agent's owner key + v=27/28 → `handleSignTelegramLink` ✓
- Registered in `main()` → Step 4 ✓

**Parity review gate (do at review, not testable by round-trip alone):** diff `computeTelegramLinkDigest`'s type string + `structPacked` `abi.Arguments` order against backend `internal/signing/telegram_link_commitment.go` (type string line ~17; struct pack `{bytes32},{uint256},{bytes32},{uint256}` + args `typehash, agentID, nonce32, expiry` lines ~141-152). They MUST be identical. (Round-trip sign/recover is self-consistent and would NOT catch a field-order swap — this manual diff is the guard.)

**Placeholder scan:** the test file's `hexKey`/`hexTo65` are called out as stubs to replace inline (Step 1 note) — replace them before running; no other placeholders.

**Type consistency:** `signTelegramLinkInput.Commitment` is `telegramLinkCommitmentPayload`; `handleSignTelegramLink` reads `in.Commitment.Message.AgentID` (string) for `KeyFor` and passes `in.Commitment` to `computeTelegramLinkDigest`. `signOutput` (existing) is the return. Consistent with the cashback sibling.

**Verification beyond unit tests:** true end-to-end signer↔backend parity (agent signs → backend `RecoverTelegramLinkSigner` accepts) is exercised by REF-158 (e2e) / REF-157 (manual QA). This ticket's gate = the type-string pin + round-trip + the parity review diff above.

## Out of scope
- Backend `link_telegram` (already merged in REF-151).
- Wiring the signer into any orchestration / the concierge.
- A golden cross-module digest vector (deferred to REF-158 e2e, which runs the real signer against the real backend).
