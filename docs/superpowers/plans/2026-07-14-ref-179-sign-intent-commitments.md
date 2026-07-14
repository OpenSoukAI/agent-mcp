# REF-179: referrer-signer sign_intent_access + sign_intent_mark commitments — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two referrer-signer MCP tools (`sign_intent_access_commitment`, `sign_intent_mark_commitment`) that produce the owner-wallet EIP-712 signatures the backend's `get_pending_intents` / `mark_intent_executed` step-2 verify, unblocking the agent's end-to-end intent poll/report loop.

**Architecture:** Mirror the existing `cmd/signer/telegram_link.go` (REF-174) byte-for-byte. Each tool: accept the `commitment` payload from the backend's step 1, recompute the EIP-712 digest locally (the `Types`/`PrimaryType` envelope is accepted but ignored — the digest reads domain + message verbatim), look up the owner key via `signerKeys.KeyFor(agentId)`, `crypto.Sign`, normalize `v` to 27/28, return `signOutput{Signature}`.

**Tech Stack:** Go; go-ethereum `crypto`/`accounts/abi`/`common`; `github.com/modelcontextprotocol/go-sdk/mcp` (`sdkmcp`). Repo `agent-mcp`, PRs → `main`.

## Global Constraints
- Field order + domain in each commitment MUST match the backend byte-for-byte, else every signature fails backend verification:
  - `IntentAccessCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)` — backend `internal/signing/intent_access_commitment.go`.
  - `IntentMarkCommitment(uint256 agentId,string intentId,string result,bytes32 nonce,uint256 expiry)` — backend `internal/signing/intent_mark_commitment.go`.
- Both share domain name `ReferrerIntentAccess`, version `1`, `chainId`, `verifyingContract` = the chain's ReviewRegistry address (all read verbatim from the passed-in `commitment.domain`).
- **String members (`intentId`, `result`) are packed as `crypto.Keccak256Hash([]byte(value))` → bytes32.** Do NOT use `abiString` in the struct pack — the backend packs the keccak of the string, not the abi-encoded string. `result` is optional; empty string `""` is a valid signed value (`keccak256([]byte(""))` is a defined constant).
- Reuse existing shared helpers (do not redefine): `commitmentDomain`, `domainTypehash`, `abiBytes32`/`abiUint256`/`abiAddress`, `hexToBytes32`, `signOutput`, `signerKeys.KeyFor(agentID string)`. `crypto.Sign` returns v=0/1 → `sig[64] += 27`.

## File Structure
- Create `cmd/signer/intent_access.go` — `sign_intent_access_commitment` (near-verbatim copy of `telegram_link.go`).
- Create `cmd/signer/intent_mark.go` — `sign_intent_mark_commitment` (template + two keccak'd string members, 6-arg struct pack).
- Create `cmd/signer/intent_access_test.go`, `cmd/signer/intent_mark_test.go` — type-string pin + round-trip (mirror `telegram_link_test.go`).
- Modify `cmd/signer/main.go` — register both tools next to `sign_telegram_link_commitment` (~line 1042).

---

### Task 1: sign_intent_access_commitment

**Files:**
- Create: `cmd/signer/intent_access.go`
- Test: `cmd/signer/intent_access_test.go`
- Modify: `cmd/signer/main.go` (register tool)

**Interfaces:**
- Consumes (existing, defined in main.go / telegram_link.go): `commitmentDomain`, `domainTypehash`, `abiBytes32`, `abiUint256`, `abiAddress`, `hexToBytes32`, `signOutput`, `signerKeys.KeyFor(string)`.
- Produces: `handleSignIntentAccess(context.Context, *sdkmcp.CallToolRequest, signIntentAccessInput) (*sdkmcp.CallToolResult, signOutput, error)`; types `signIntentAccessInput{Commitment intentAccessCommitmentPayload}`, `intentAccessCommitmentPayload{Types,PrimaryType,Domain commitmentDomain,Message intentAccessCommitmentMessage}`, `intentAccessCommitmentMessage{AgentID,Nonce,Expiry string}`; const `intentAccessCommitmentTypeString`.

- [ ] **Step 1: Write the failing tests** (`cmd/signer/intent_access_test.go`) — mirror `telegram_link_test.go`:

```go
package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixedIntentAccessPayload() intentAccessCommitmentPayload {
	return intentAccessCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerIntentAccess",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: intentAccessCommitmentMessage{
			AgentID: "7",
			Nonce:   "0x" + strings.Repeat("ab", 32),
			Expiry:  "1893456000",
		},
	}
}

func TestIntentAccessTypeString_MatchesBackend(t *testing.T) {
	const want = "IntentAccessCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)"
	if intentAccessCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", intentAccessCommitmentTypeString, want)
	}
}

func TestSignIntentAccess_RoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	p := fixedIntentAccessPayload()
	_, out, err := handleSignIntentAccess(nil, nil, signIntentAccessInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignIntentAccess: %v", err)
	}
	digest, err := computeIntentAccessDigest(p)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("sig: err=%v len=%d", err, len(sig))
	}
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
```

- [ ] **Step 2: Run — verify it fails** (`go test ./cmd/signer/ -run IntentAccess`) — Expected: FAIL/compile error (symbols undefined).

- [ ] **Step 3: Implement `cmd/signer/intent_access.go`** — copy `telegram_link.go`, rename `telegram*`→`intentAccess*`, type string → `IntentAccessCommitment(uint256 agentId,bytes32 nonce,uint256 expiry)`, domain-name doc const → `"ReferrerIntentAccess"`. `computeIntentAccessDigest` is identical to `computeTelegramLinkDigest` but packs `intentAccessCommitmentTypehash`. Struct pack stays `abi.Arguments{ {abiBytes32},{abiUint256},{abiBytes32},{abiUint256} }.Pack(intentAccessCommitmentTypehash, agentID, nonce, expiry)`. `handleSignIntentAccess` uses `signerKeys.KeyFor(in.Commitment.Message.AgentID)`, sign, `sig[64] += 27`, return `signOutput{Signature}`.

- [ ] **Step 4: Register the tool in `main.go`** (after the `sign_telegram_link_commitment` AddTool block, ~line 1048):

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_intent_access_commitment",
		Description: "Sign an EIP-712 IntentAccessCommitment using the agent's owner private key. " +
			"Call this between get_pending_intents step 1 and step 2: pass the 'commitment' object from " +
			"get_pending_intents step 1 exactly as returned, then use the returned 'signature' as 'agent_sig' " +
			"in get_pending_intents step 2 (with the same nonce and expiry).",
	}, handleSignIntentAccess)
```

- [ ] **Step 5: Run tests — verify pass** (`go test ./cmd/signer/ -run IntentAccess`) — Expected: PASS.

- [ ] **Step 6: Commit** — `feat(signer): sign_intent_access_commitment (REF-179)`.

---

### Task 2: sign_intent_mark_commitment

**Files:**
- Create: `cmd/signer/intent_mark.go`
- Test: `cmd/signer/intent_mark_test.go`
- Modify: `cmd/signer/main.go` (register tool)

**Interfaces:**
- Consumes: same shared helpers as Task 1, plus `crypto.Keccak256Hash`.
- Produces: `handleSignIntentMark(...)`; types `signIntentMarkInput{Commitment intentMarkCommitmentPayload}`, `intentMarkCommitmentPayload{...,Message intentMarkCommitmentMessage}`, `intentMarkCommitmentMessage{AgentID,IntentID,Result,Nonce,Expiry string}`; const `intentMarkCommitmentTypeString`.

- [ ] **Step 1: Write the failing tests** (`cmd/signer/intent_mark_test.go`):

```go
package main

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixedIntentMarkPayload() intentMarkCommitmentPayload {
	return intentMarkCommitmentPayload{
		Domain: commitmentDomain{
			Name:              "ReferrerIntentAccess",
			Version:           "1",
			ChainID:           84532,
			VerifyingContract: "0x000000000000000000000000000000000000aBcD",
		},
		Message: intentMarkCommitmentMessage{
			AgentID:  "7",
			IntentID: "01890a5d-ac96-774b-bcce-b302099a8057",
			Result:   "escrow#42",
			Nonce:    "0x" + strings.Repeat("cd", 32),
			Expiry:   "1893456000",
		},
	}
}

func TestIntentMarkTypeString_MatchesBackend(t *testing.T) {
	const want = "IntentMarkCommitment(uint256 agentId,string intentId,string result,bytes32 nonce,uint256 expiry)"
	if intentMarkCommitmentTypeString != want {
		t.Fatalf("type string drift:\n got  %q\n want %q", intentMarkCommitmentTypeString, want)
	}
}

func TestSignIntentMark_RoundTrip(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	want := crypto.PubkeyToAddress(key.PublicKey)
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	p := fixedIntentMarkPayload()
	_, out, err := handleSignIntentMark(nil, nil, signIntentMarkInput{Commitment: p})
	if err != nil {
		t.Fatalf("handleSignIntentMark: %v", err)
	}
	digest, err := computeIntentMarkDigest(p)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(out.Signature, "0x"))
	if err != nil || len(sig) != 65 {
		t.Fatalf("sig: err=%v len=%d", err, len(sig))
	}
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

// Changing intentId or result must change the digest — proves both string
// members are bound into the struct hash (not dropped).
func TestSignIntentMark_BindsIntentIDAndResult(t *testing.T) {
	base := fixedIntentMarkPayload()
	d0, _ := computeIntentMarkDigest(base)

	pID := fixedIntentMarkPayload()
	pID.Message.IntentID = "different-intent-id"
	dID, _ := computeIntentMarkDigest(pID)
	if hex.EncodeToString(d0) == hex.EncodeToString(dID) {
		t.Fatal("digest unchanged when intentId changed — intentId not bound")
	}

	pRes := fixedIntentMarkPayload()
	pRes.Message.Result = "escrow#99"
	dRes, _ := computeIntentMarkDigest(pRes)
	if hex.EncodeToString(d0) == hex.EncodeToString(dRes) {
		t.Fatal("digest unchanged when result changed — result not bound")
	}
}

// Empty result is a valid signed value.
func TestSignIntentMark_EmptyResultOK(t *testing.T) {
	p := fixedIntentMarkPayload()
	p.Message.Result = ""
	if _, err := computeIntentMarkDigest(p); err != nil {
		t.Fatalf("empty result should be valid: %v", err)
	}
}
```

- [ ] **Step 2: Run — verify it fails** (`go test ./cmd/signer/ -run IntentMark`) — Expected: FAIL (symbols undefined).

- [ ] **Step 3: Implement `cmd/signer/intent_mark.go`**:

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

// IntentMarkCommitment EIP-712 — must match backend signing/intent_mark_commitment.go exactly.
// Dedicated type binds the specific intentId + result being recorded, so a mark signature cannot be
// replayed against a different intent or to record a forged result, nor reused as a read (IntentAccess).
const intentMarkCommitmentTypeString = "IntentMarkCommitment(uint256 agentId,string intentId,string result,bytes32 nonce,uint256 expiry)"

var intentMarkCommitmentTypehash = crypto.Keccak256Hash([]byte(intentMarkCommitmentTypeString))

const intentMarkDomainName = "ReferrerIntentAccess" // documentation-only; digest reads domain verbatim

type intentMarkCommitmentMessage struct {
	AgentID  string `json:"agentId"`
	IntentID string `json:"intentId"`
	Result   string `json:"result"`
	Nonce    string `json:"nonce"`
	Expiry   string `json:"expiry"`
}

type intentMarkCommitmentPayload struct {
	Types       map[string]any              `json:"types,omitempty"`
	PrimaryType string                      `json:"primaryType,omitempty"`
	Domain      commitmentDomain            `json:"domain"`
	Message     intentMarkCommitmentMessage `json:"message"`
}

type signIntentMarkInput struct {
	Commitment intentMarkCommitmentPayload `json:"commitment"`
}

func computeIntentMarkDigest(p intentMarkCommitmentPayload) ([]byte, error) {
	contractAddr := common.HexToAddress(p.Domain.VerifyingContract)
	chainID := new(big.Int).SetInt64(p.Domain.ChainID)

	domainPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256}, {Type: abiAddress},
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

	// intentId + result are EIP-712 string members: each contributes keccak256(bytes(value))
	// packed as bytes32, in the order agentId, intentId, result, nonce, expiry.
	structPacked, err := abi.Arguments{
		{Type: abiBytes32}, {Type: abiUint256}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiBytes32}, {Type: abiUint256},
	}.Pack(
		intentMarkCommitmentTypehash,
		agentID,
		crypto.Keccak256Hash([]byte(p.Message.IntentID)),
		crypto.Keccak256Hash([]byte(p.Message.Result)),
		nonce,
		expiry,
	)
	if err != nil {
		return nil, fmt.Errorf("pack struct: %w", err)
	}
	structHash := crypto.Keccak256Hash(structPacked)

	return crypto.Keccak256([]byte{0x19, 0x01}, domainSeparator[:], structHash[:]), nil
}

func handleSignIntentMark(
	_ context.Context,
	_ *sdkmcp.CallToolRequest,
	in signIntentMarkInput,
) (*sdkmcp.CallToolResult, signOutput, error) {
	privKey, err := signerKeys.KeyFor(in.Commitment.Message.AgentID)
	if err != nil {
		return nil, signOutput{}, err
	}
	digest, err := computeIntentMarkDigest(in.Commitment)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("compute digest: %w", err)
	}
	sig, err := crypto.Sign(digest, privKey)
	if err != nil {
		return nil, signOutput{}, fmt.Errorf("sign: %w", err)
	}
	sig[64] += 27
	return nil, signOutput{Signature: "0x" + hex.EncodeToString(sig)}, nil
}
```

- [ ] **Step 4: Register the tool in `main.go`** (after the Task-1 block):

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "sign_intent_mark_commitment",
		Description: "Sign an EIP-712 IntentMarkCommitment using the agent's owner private key. " +
			"Call this between mark_intent_executed step 1 and step 2: pass the 'commitment' object from " +
			"mark_intent_executed step 1 exactly as returned (it binds intent_id and result), then use the " +
			"returned 'signature' as 'agent_sig' in mark_intent_executed step 2 (with the same intent_id, " +
			"result, nonce, and expiry).",
	}, handleSignIntentMark)
```

- [ ] **Step 5: Run tests — verify pass** (`go test ./cmd/signer/ -run IntentMark`) — Expected: PASS.

- [ ] **Step 6: Full build + suite** (`go build ./... && go vet ./... && go test ./...`) — Expected: all green.

- [ ] **Step 7: Commit** — `feat(signer): sign_intent_mark_commitment (REF-179)`.

---

## Self-Review notes
- Spec coverage: Task 1 = read signature (get_pending_intents); Task 2 = mark signature (mark_intent_executed) incl. result binding. Covers both acceptance bullets in REF-179.
- Type consistency: shared helper names (`commitmentDomain`, `domainTypehash`, `abiBytes32/Uint256/Address`, `hexToBytes32`, `signOutput`, `signerKeys.KeyFor`) match the existing signer. Both new commitment type names are distinct (`intentAccess*` / `intentMark*`).
- No `abiString` in either struct pack — string members are keccak'd to bytes32 (the trap that would silently break backend verification).
- Post-implementation verification: byte-parity of both digests vs backend `intent_access_commitment.go` / `intent_mark_commitment.go` (domain pack, struct pack order, `0x1901` digest). Ideally cross-check by recovering with the backend's recover functions if a cross-repo harness is feasible; otherwise the type-string pin + round-trip + pack-order review is the guard (same as REF-174).
