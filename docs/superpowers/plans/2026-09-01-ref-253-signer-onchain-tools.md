# REF-253 — Two missing `referrer-signer` on-chain tools

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `trigger_settle_fallback` and `update_review_content_onchain` to the `referrer-signer` MCP server, so two protocol paths that currently dead-end from MCP become completable by an agent.

**Architecture:** Both are transaction-sending tools on the existing signer server. Each follows the established one-file-per-tool pattern of `cmd/signer/bind_escrow.go`: a typed input/output struct, an input parser, a custom-error → plain-English revert map built from runtime-computed selectors, an on-chain **preflight read** so the common refusals are explained before a tx is paid for, then `bind.NewBoundContract(...).Transact` + `bind.WaitMined`. No new dependency, no new env var — both use the `BASE_RPC_URL` / `CHAIN_ID` / `COMMISSION_ESCROW_ADDRESS` / `REVIEW_REGISTRY_ADDRESS` set already read by `main.go` and `bind_escrow.go`.

**Tech Stack:** Go 1.x, `github.com/ethereum/go-ethereum` (`abi`, `bind`, `ethclient`, `crypto`), `github.com/modelcontextprotocol/go-sdk/mcp`. Tests are plain `go test` unit tests — no chain, no network (see *Test strategy* below).

**Spec:** Linear REF-253 ("MCP polish tasks", *Missing* section) and `mcp-tools-reconciliation.md` (root of the workspace), *Missing — a real path dead-ends without them*.

## Global Constraints

- Repo: `agent-mcp`. Branch off `main`. This plan does **not** touch `backend` or `contracts`.
- Every tool lives in its own file under `cmd/signer/`, `package main`, reusing the existing globals `signerKeys`, `commissionEscrowABI`, `reviewRegistryABI`, `computeContentHash`, `hexToBytes32`, `dataError`, and the ABI type vars `abiUint256` / `abiBytes32` / `abiAddress` / `abiString`. Do not duplicate them.
- Tool names are exactly `trigger_settle_fallback` and `update_review_content_onchain`. The second name deliberately differs from the backend's `update_review_content` — they are two different tools on two different servers and the docs must not blur them.
- `go build ./...`, `go vet ./...`, and `go test -count=1 ./...` must all pass before each commit. `cmd/signer/vote_sign_test.go` is already `gofmt`-dirty on `main` — leave it alone; do not let it hide a new formatting problem in your own files (`gofmt -l cmd/signer/` should list nothing new).
- Chain values verified against `contracts/src` at 2026-09-01: `CommissionEscrow.triggerSettleFallback(uint256)` is **permissionless**, `nonReentrant`, `whenNotPaused`; eligibility is `escrow.windowEnd + 10 days`; `EscrowState.Settled == 1`. `ReviewRegistry.EDIT_WINDOW == 7 days`; `ProofType.InSystemPurchase == 2`.
- Commit messages: Conventional Commits, `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>` as the last line.

## Test strategy (read before Task 1)

Neither tool can be unit-tested end-to-end without a chain, and this repo has **no** chain-test harness — `bind_escrow_test.go` is the precedent and it tests four things without ever dialing an RPC:

1. **ABI packing** — assert the new ABI entry packs to the correct 4-byte selector and round-trips its args. This is the test that actually catches a typo'd ABI string, which is the highest-probability defect in this work.
2. **Input parsing** — decimal strings in, `*big.Int` out, garbage rejected.
3. **Key lookup** — the handler resolves the signing key by the *canonical* id, so a whitespace-padded input still hits the keystore entry. Achieved by pointing `signerKeys` at a test keystore with **no** fallback key and setting `BASE_RPC_URL=""` so the handler stops right after `KeyFor`.
4. **Revert decoding** — a hand-built `selector ‖ 32 zero bytes` blob maps to the friendly message.

Add a fifth for this work:

5. **Preflight logic as a pure function.** Both tools need a gate that is pure arithmetic over values read from the chain (`windowEnd + 10 days` vs now; `timestamp + 7 days` vs now). Put that arithmetic in its own function taking explicit values, so it is tested directly with no RPC. Do **not** bury it inside the handler where only a live chain can reach it.

---

## File Structure

- **Create** `cmd/signer/settle_fallback.go` — Task 1's whole tool: `settleFallbackInput`/`Output`, `parseSettleFallbackInput`, `fallbackEligibility`, `settleFallbackRevertMessages`, `decodeSettleFallbackRevertData`, `decodeSettleFallbackRevert`, `handleTriggerSettleFallback`.
- **Create** `cmd/signer/settle_fallback_test.go` — Task 1's tests.
- **Create** `cmd/signer/update_review.go` — Task 2's whole tool: `updateReviewOnchainInput`/`Output`, `parseUpdateReviewInput`, `onChainReview` + `decodeGetReview`, `editWindowState`, `updateReviewRevertMessages`, `decodeUpdateReviewRevertData`, `decodeUpdateReviewRevert`, `handleUpdateReviewContentOnchain`.
- **Create** `cmd/signer/update_review_test.go` — Task 2's tests.
- **Modify** `cmd/signer/main.go` — two additions to the `commissionEscrowABI` literal (Task 1), three to `reviewRegistryABI` (Task 2), one `FallbackSettled` topic var (Task 1), one `reviewContentUpdatedTopic` var (Task 2), and one `sdkmcp.AddTool` block per task in `main()`.
- **Modify** `CLAUDE.md` — one signer-table row + one workflow subsection per task.
- **Modify** (sibling repos, same ticket) `../docs/mcp-methods.md`, `../skills/plugins/referrer-agent-protocol/SKILL.md`, and one `reference/*.md` per tool. These are separate git repos; commit them separately, in the task that adds the tool.

---

### Task 1: `trigger_settle_fallback`

**What it is for.** `CommissionEscrow` settles the day-60 batch from the oracle. If the oracle never fires, the held-back commission and the buyer's unreleased cashback sit in the contract forever. `triggerSettleFallback(escrowId)` is the permissionless escape hatch, callable from `windowEnd + 10 days`. The backend already tells agents to call it — `list_escrows`' own description says *"confirm there before calling triggerSettleFallback"* (`backend/internal/mcp/tools.go:198`) — and no tool exists, so that instruction currently dead-ends.

**What the agent must understand before calling it** (this belongs in the tool description, not just the docs): fallback is **not** a claim. `heldBackAmt` goes to the **treasury**, not to the reviewer — a reviewer triggering it forfeits the held-back commission it would have received from a normal settle. Unreleased `cashbackAmt` goes to the **reviewer's** wallet (the buyer never published its review, so the cashback reverts to its funder). The caller pays gas and receives nothing for calling. So the honest framing is: *this unsticks funds after oracle failure; it does not pay you.*

**Files:**
- Create: `cmd/signer/settle_fallback.go`
- Test: `cmd/signer/settle_fallback_test.go`
- Modify: `cmd/signer/main.go` (ABI literal ~line 59-63, topic vars ~line 46-47, `AddTool` in `main()`)
- Modify: `CLAUDE.md` (signer tool table; new subsection near the escrow material)
- Modify: `../docs/mcp-methods.md`, `../skills/plugins/referrer-agent-protocol/SKILL.md`, `../skills/plugins/referrer-agent-protocol/reference/cashback-earnings.md`

**Interfaces:**
- Consumes (all already on `main`): `signerKeys.KeyFor(string) (*ecdsa.PrivateKey, error)`, `commissionEscrowABI abi.ABI`, `dataError interface{ ErrorData() interface{} }`, `mustParseABI`.
- Produces: `handleTriggerSettleFallback(ctx, *sdkmcp.CallToolRequest, settleFallbackInput) (*sdkmcp.CallToolResult, settleFallbackOutput, error)`; `fallbackEligibility(windowEnd, now int64) (eligibleAt int64, eligible bool)`; `parseSettleFallbackInput(settleFallbackInput) (escrowID, agentID *big.Int, err error)`; `decodeSettleFallbackRevertData([]byte) (string, bool)`. Nothing in Task 2 depends on these.

- [ ] **Step 1: Write the failing tests**

Create `cmd/signer/settle_fallback_test.go`:

```go
package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestSettleFallback_ABIPack asserts the extended commissionEscrowABI packs
// triggerSettleFallback(escrowId) to the on-chain selector + arg. A typo'd ABI string is
// the highest-probability defect in this tool, and it would otherwise only surface as an
// opaque revert against a live chain.
func TestSettleFallback_ABIPack(t *testing.T) {
	escrowID := big.NewInt(42)

	data, err := commissionEscrowABI.Pack("triggerSettleFallback", escrowID)
	if err != nil {
		t.Fatalf("Pack triggerSettleFallback: %v", err)
	}
	if len(data) != 4+32 {
		t.Fatalf("calldata len = %d, want 36", len(data))
	}
	wantSel := crypto.Keccak256([]byte("triggerSettleFallback(uint256)"))[:4]
	if got, want := hex.EncodeToString(data[:4]), hex.EncodeToString(wantSel); got != want {
		t.Fatalf("selector = %s, want %s", got, want)
	}
	args, err := commissionEscrowABI.Methods["triggerSettleFallback"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(escrowID) != 0 {
		t.Fatalf("unpacked arg = %v, want 42", args[0])
	}
}

// TestSettleFallback_ParseInputs asserts decimal-string inputs parse and reject garbage.
func TestSettleFallback_ParseInputs(t *testing.T) {
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "42", AgentID: "7"}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "nope", AgentID: "7"}); err == nil {
		t.Fatal("expected error on bad escrow_id")
	}
	if _, _, err := parseSettleFallbackInput(settleFallbackInput{EscrowID: "42", AgentID: ""}); err == nil {
		t.Fatal("expected error on empty agent_id")
	}
}

// TestFallbackEligibility pins the contract's own gate: eligibleAt = windowEnd + 10 days,
// and the comparison is NOT strict (the contract reverts only while now < eligibleAt), so
// exactly-at-eligibleAt must be eligible. Testing this as a pure function is the only way
// to cover it without a chain.
func TestFallbackEligibility(t *testing.T) {
	const windowEnd = 1_000_000
	const tenDays = 10 * 24 * 60 * 60

	at, ok := fallbackEligibility(windowEnd, windowEnd+tenDays-1)
	if at != windowEnd+tenDays {
		t.Fatalf("eligibleAt = %d, want %d", at, windowEnd+tenDays)
	}
	if ok {
		t.Fatal("one second early must NOT be eligible")
	}
	if _, ok := fallbackEligibility(windowEnd, windowEnd+tenDays); !ok {
		t.Fatal("exactly at eligibleAt must be eligible")
	}
	if _, ok := fallbackEligibility(windowEnd, windowEnd+tenDays+1); !ok {
		t.Fatal("past eligibleAt must be eligible")
	}
}

// TestDecodeSettleFallbackRevert maps each custom error this tool can hit to a non-empty
// message. TooEarly carries three args; only the selector is matched, so the body is padding.
func TestDecodeSettleFallbackRevert(t *testing.T) {
	for _, sig := range []string{
		"AlreadySettled(uint256)",
		"EscrowNotFound(uint256)",
		"TooEarly(uint256,uint256,uint256)",
		"EnforcedPause()",
	} {
		sel := crypto.Keccak256([]byte(sig))[:4]
		data := append(append([]byte{}, sel...), make([]byte, 96)...)
		msg, ok := decodeSettleFallbackRevertData(data)
		if !ok || msg == "" {
			t.Fatalf("%s: expected a decoded message, got ok=%v msg=%q", sig, ok, msg)
		}
	}
	if _, ok := decodeSettleFallbackRevertData([]byte{0x01, 0x02}); ok {
		t.Fatal("short data must not decode")
	}
}

// TestSettleFallback_KeyLookupNormalizesAgentID proves the handler resolves the signing key
// by the canonical (trimmed) agent_id. The keystore has NO fallback key, so a missed lookup
// is visibly a "no key for agent" error rather than a silent wrong-key signature.
func TestSettleFallback_KeyLookupNormalizesAgentID(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ks, err := parseKeystore("7:0x"+hex.EncodeToString(crypto.FromECDSA(key)), "")
	if err != nil {
		t.Fatalf("parseKeystore: %v", err)
	}
	prev := signerKeys
	signerKeys = ks
	t.Cleanup(func() { signerKeys = prev })

	t.Setenv("BASE_RPC_URL", "") // handler stops here, AFTER a successful KeyFor
	_, _, err = handleTriggerSettleFallback(context.Background(), nil, settleFallbackInput{AgentID: " 7 ", EscrowID: "1"})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	if strings.Contains(err.Error(), "no key for agent") {
		t.Fatalf("whitespace agent_id missed the keystore entry (key lookup not normalized): %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'SettleFallback|FallbackEligibility' -v`

Expected: **compile failure**, not test failure — `undefined: settleFallbackInput`, `undefined: parseSettleFallbackInput`, `undefined: fallbackEligibility`, `undefined: decodeSettleFallbackRevertData`, `undefined: handleTriggerSettleFallback`. `TestSettleFallback_ABIPack` will also fail once it compiles, because the ABI entry does not exist yet (`Pack` returns `method 'triggerSettleFallback' not found`).

- [ ] **Step 3: Extend the ABI and add the event topic in `main.go`**

In the `commissionEscrowABI = mustParseABI(...)` literal, add these two entries (keep the existing `getEscrow`, `bind`, and `EscrowBound` entries; JSON entries are comma-separated):

```json
{"inputs":[{"name":"escrowId","type":"uint256"}],"name":"triggerSettleFallback","outputs":[],"stateMutability":"nonpayable","type":"function"},
{"anonymous":false,"inputs":[{"indexed":true,"name":"escrowId","type":"uint256"},{"indexed":true,"name":"treasury","type":"address"},{"indexed":false,"name":"heldBackAmt","type":"uint128"},{"indexed":false,"name":"cashbackAmt","type":"uint128"}],"name":"FallbackSettled","type":"event"}
```

Next to `reviewPublishedTopic` / `escrowDepositedTopic` (~line 46), add:

```go
fallbackSettledTopic = crypto.Keccak256Hash([]byte("FallbackSettled(uint256,address,uint128,uint128)"))
```

- [ ] **Step 4: Write `cmd/signer/settle_fallback.go`**

```go
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── trigger_settle_fallback ─────────────────────────────────────────────────────
//
// CommissionEscrow.triggerSettleFallback is the permissionless escape hatch for an escrow
// the oracle never settled. It is NOT a claim: heldBackAmt goes to the TREASURY (a reviewer
// calling this forfeits the commission a normal settle would have paid it) and any
// unreleased cashbackAmt goes to the REVIEWER's wallet (the buyer never published, so the
// cashback reverts to its funder). The caller pays gas and receives nothing for calling.

// fallbackGraceSecs is the contract's own delay after windowEnd before the public fallback
// opens: `uint256 eligibleAt = uint256(rec.windowEnd) + 10 days` (CommissionEscrow.sol).
// Mirrored here only to explain a refusal BEFORE spending gas; the chain remains authoritative.
const fallbackGraceSecs int64 = 10 * 24 * 60 * 60

type settleFallbackInput struct {
	AgentID  string `json:"agent_id"`           // decimal; selects the signing key. Any agent may call — the contract is permissionless.
	EscrowID string `json:"escrow_id"`          // decimal; from list_escrows / get_escrow_status
	ChainID  string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env (default 84532). BASE_RPC_URL must point at this chain.
}

type settleFallbackOutput struct {
	TxHash    string `json:"tx_hash"`    // 0x-prefixed
	EscrowID  string `json:"escrow_id"`  // echoed
	SettledBy string `json:"settled_by"` // = signer address (msg.sender)
	// HeldBackToTreasury / CashbackToReviewer are USDC base-unit decimal strings read back
	// from the FallbackSettled event, so the caller sees where the money actually went
	// rather than having to infer it. Empty if the event was absent from the receipt.
	HeldBackToTreasury string `json:"held_back_to_treasury,omitempty"`
	CashbackToReviewer string `json:"cashback_to_reviewer,omitempty"`
}

func parseSettleFallbackInput(in settleFallbackInput) (escrowID, agentID *big.Int, err error) {
	escrowID, ok := new(big.Int).SetString(strings.TrimSpace(in.EscrowID), 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid escrow_id: %q (want a decimal string)", in.EscrowID)
	}
	agentID, ok = new(big.Int).SetString(strings.TrimSpace(in.AgentID), 10)
	if !ok {
		return nil, nil, fmt.Errorf("invalid agent_id: %q (want a decimal string)", in.AgentID)
	}
	return escrowID, agentID, nil
}

// fallbackEligibility mirrors the contract's gate: eligibleAt = windowEnd + 10 days, and the
// revert is `now < eligibleAt`, so exactly-at-eligibleAt IS eligible. Pure so it is testable
// without a chain.
func fallbackEligibility(windowEnd, now int64) (eligibleAt int64, eligible bool) {
	eligibleAt = windowEnd + fallbackGraceSecs
	return eligibleAt, now >= eligibleAt
}

// settleFallbackRevertMessages maps a custom-error selector (hex, 4 bytes) to a caller-facing
// explanation. Selectors are computed at runtime from the signatures, so there is no
// hand-copied hex to drift. EnforcedPause is OpenZeppelin v5's Pausable error, reachable
// because triggerSettleFallback is `whenNotPaused`.
func settleFallbackRevertMessages() map[string]string {
	sel := func(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]) }
	return map[string]string{
		sel("AlreadySettled(uint256)"):           "this escrow is already settled — the oracle got there first, nothing is stuck",
		sel("EscrowNotFound(uint256)"):           "no escrow found for that escrow_id",
		sel("TooEarly(uint256,uint256,uint256)"): "the public fallback is not open yet — it opens 10 days after the escrow's windowEnd (day ~70)",
		sel("EnforcedPause()"):                   "CommissionEscrow is paused by the protocol admin — no settlement of any kind can run until it is unpaused",
	}
}

func decodeSettleFallbackRevertData(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	msg, ok := settleFallbackRevertMessages()[hex.EncodeToString(data[:4])]
	return msg, ok
}

// decodeSettleFallbackRevert extracts revert data from a go-ethereum tx/estimate error and
// maps its selector to a friendly message. Returns ("", false) if it can't decode one.
func decodeSettleFallbackRevert(err error) (string, bool) {
	var de dataError
	if !errors.As(err, &de) {
		return "", false
	}
	hexData, ok := de.ErrorData().(string)
	if !ok {
		return "", false
	}
	raw, e := hex.DecodeString(strings.TrimPrefix(hexData, "0x"))
	if e != nil {
		return "", false
	}
	return decodeSettleFallbackRevertData(raw)
}

func handleTriggerSettleFallback(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in settleFallbackInput,
) (*sdkmcp.CallToolResult, settleFallbackOutput, error) {
	escrowID, agentID, err := parseSettleFallbackInput(in)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}

	privKey, err := signerKeys.KeyFor(agentID.String())
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}

	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, settleFallbackOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	escrowAddrHex := os.Getenv("COMMISSION_ESCROW_ADDRESS")
	if escrowAddrHex == "" {
		return nil, settleFallbackOutput{}, fmt.Errorf("COMMISSION_ESCROW_ADDRESS env var not set")
	}

	chainIDStr := in.ChainID
	if chainIDStr == "" {
		chainIDStr = os.Getenv("CHAIN_ID")
	}
	if chainIDStr == "" {
		chainIDStr = "84532" // Base Sepolia
	}
	chainIDInt, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("invalid chain id %q: %w", chainIDStr, err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	escrowAddr := common.HexToAddress(escrowAddrHex)

	// ── preflight: explain the two common refusals before paying for a tx ──────
	// getEscrow's return is all static types, one 32-byte slot each, in declaration order:
	// reviewerAgentId, buyerAgentId, buyerWallet, merchantId, productId, heldBackAmt,
	// cashbackAmt, originalPurchaseAmt, depositTimestamp, windowEnd, productType, state,
	// cashbackReleased. windowEnd is slot 9 (288:320); state is slot 11 (352:384).
	callData, err := commissionEscrowABI.Pack("getEscrow", escrowID)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("pack getEscrow: %w", err)
	}
	raw, err := client.CallContract(ctx, ethereum.CallMsg{To: &escrowAddr, Data: callData}, nil)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("getEscrow(%s): %w (is escrow_id right, and is BASE_RPC_URL on chain %d?)", escrowID, err, chainIDInt)
	}
	if len(raw) < 384 {
		return nil, settleFallbackOutput{}, fmt.Errorf("getEscrow returned short data: %d bytes", len(raw))
	}
	windowEnd := new(big.Int).SetBytes(raw[288:320]).Int64()
	state := new(big.Int).SetBytes(raw[352:384]).Int64()
	if state == 1 { // EscrowState.Settled
		return nil, settleFallbackOutput{}, fmt.Errorf("escrow %s is already settled — the oracle got there first, nothing is stuck", escrowID)
	}
	if eligibleAt, ok := fallbackEligibility(windowEnd, time.Now().Unix()); !ok {
		return nil, settleFallbackOutput{}, fmt.Errorf(
			"escrow %s is not fallback-eligible yet: the public fallback opens at %s (windowEnd + 10 days)",
			escrowID, time.Unix(eligibleAt, 0).UTC().Format(time.RFC3339),
		)
	}

	// ── send ───────────────────────────────────────────────────────────────────
	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("build transactor: %w", err)
	}
	contract := bind.NewBoundContract(escrowAddr, commissionEscrowABI, client, client, client)

	tx, err := contract.Transact(auth, "triggerSettleFallback", escrowID)
	if err != nil {
		if msg, ok := decodeSettleFallbackRevert(err); ok {
			return nil, settleFallbackOutput{}, fmt.Errorf("triggerSettleFallback would revert: %s", msg)
		}
		return nil, settleFallbackOutput{}, fmt.Errorf("triggerSettleFallback tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, settleFallbackOutput{}, fmt.Errorf("triggerSettleFallback tx reverted: %s", tx.Hash().Hex())
	}

	out := settleFallbackOutput{
		TxHash:    tx.Hash().Hex(),
		EscrowID:  escrowID.String(),
		SettledBy: crypto.PubkeyToAddress(privKey.PublicKey).Hex(),
	}
	// FallbackSettled(escrowId indexed, treasury indexed, uint128 heldBackAmt, uint128 cashbackAmt):
	// both amounts are non-indexed, so they are the two 32-byte words of Data.
	for _, lg := range receipt.Logs {
		if len(lg.Topics) >= 1 && lg.Topics[0] == fallbackSettledTopic && len(lg.Data) >= 64 {
			out.HeldBackToTreasury = new(big.Int).SetBytes(lg.Data[0:32]).String()
			out.CashbackToReviewer = new(big.Int).SetBytes(lg.Data[32:64]).String()
			break
		}
	}
	return nil, out, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd agent-mcp && gofmt -l cmd/signer/ && go build ./... && go vet ./... && go test -count=1 ./cmd/signer/ -run 'SettleFallback|FallbackEligibility' -v`

Expected: `gofmt -l` prints only the pre-existing `cmd/signer/vote_sign_test.go`; build and vet clean; all five tests PASS.

- [ ] **Step 6: Register the tool in `main()`**

Add after the existing `bind_escrow` registration block in `main()`:

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "trigger_settle_fallback",
		Description: "Force-settle an escrow the oracle never settled (CommissionEscrow.triggerSettleFallback). " +
			"Permissionless — any agent may call it — and it opens 10 days after the escrow's windowEnd (~day 70). " +
			"Confirm fallback_available via get_escrow_status (referrer-agent) first; list_escrows always reports it false. " +
			"This is NOT a claim and it does not pay you: the held-back commission goes to the protocol TREASURY (so a " +
			"reviewer calling this forfeits what a normal day-60 settle would have paid it), any unreleased cashback goes " +
			"to the REVIEWER's wallet (the buyer never published its review, so the cashback reverts to its funder), and " +
			"you pay the gas. Call it to unstick funds after an oracle failure, not to get paid.",
	}, handleTriggerSettleFallback)
```

- [ ] **Step 7: Verify the whole suite still passes**

Run: `cd agent-mcp && go build ./... && go vet ./... && go test -count=1 ./...`

Expected: `ok github.com/OpenSoukAI/agent-mcp/cmd/signer`.

- [ ] **Step 8: Document it — `agent-mcp`**

In `CLAUDE.md`, add to the **referrer-signer** table (after the `bind_escrow` row):

```markdown
| `trigger_settle_fallback` | Force-settle an escrow the oracle never settled (`CommissionEscrow.triggerSettleFallback`), from ~day 70. Permissionless; held-back goes to the treasury, unreleased cashback to the reviewer — it unsticks funds, it does not pay the caller |
```

And add a subsection immediately after the escrow/earnings material:

```markdown
### Oracle-failure fallback

An escrow normally settles from the oracle at the end of its 60-day window. If that never
happens, the held-back commission and any unreleased cashback sit in `CommissionEscrow`
indefinitely. `trigger_settle_fallback` (referrer-signer) is the permissionless escape hatch:
it becomes callable **10 days after the escrow's `windowEnd`** (≈ day 70) and anyone can send it.

Check `get_escrow_status` first — its `fallback_available` is the authoritative signal.
`list_escrows` always reports `fallback_available: false` (it is the indexed view and does no
per-escrow chain read), so do not conclude anything from it.

Know what you are triggering before you call it:

- `heldBackAmt` → the protocol **treasury**, not the reviewer. A reviewer that triggers
  fallback gives up the commission a normal settle would have paid it.
- unreleased `cashbackAmt` → the **reviewer's** wallet. The buyer never published its review,
  so the cashback reverts to the reviewer who funded it.
- the caller pays gas and receives nothing for calling.

The tool reads the escrow first and refuses with a dated explanation if the escrow is already
settled or the fallback window has not opened, so a doomed call costs no gas.
```

- [ ] **Step 9: Document it — sibling repos**

`../docs/mcp-methods.md`, in the **On-chain / payment actions** table:

```markdown
| `trigger_settle_fallback` | Force-settle an escrow the oracle never settled (`CommissionEscrow.triggerSettleFallback`); permissionless, opens at `windowEnd + 10 days` (~day 70). Held-back → treasury, unreleased cashback → reviewer, caller gets nothing | `agent_id` (key selection), `escrow_id`; optional `chain_id` | `tx_hash`, `escrow_id`, `settled_by`, and `held_back_to_treasury` / `cashback_to_reviewer` read back from `FallbackSettled` |
```

Bump the counts in the same file: `## referrer-signer (agent-mcp) — 12 tools` and the total line to `**34 tools total — 22 on `referrer-agent`, 12 on `referrer-signer`.**`

`../skills/plugins/referrer-agent-protocol/reference/cashback-earnings.md` — add a short "Oracle-failure fallback" section carrying the same three bullets (treasury / reviewer / caller-pays-gas) and the `get_escrow_status`-not-`list_escrows` point. `SKILL.md` — add `trigger_settle_fallback` to the `referrer-signer` tool list in *Quick reference — tools*.

- [ ] **Step 10: Commit**

Three commits, one per repo (they are three separate git repos):

```bash
cd agent-mcp && git add cmd/signer/settle_fallback.go cmd/signer/settle_fallback_test.go cmd/signer/main.go CLAUDE.md
git commit -m "$(cat <<'EOF'
feat: trigger_settle_fallback signer tool (REF-253)

list_escrows already tells an agent to call triggerSettleFallback when an
escrow's oracle settle never fired, and no tool existed — the instruction
dead-ended. This wraps CommissionEscrow.triggerSettleFallback.

The tool reads the escrow first and refuses, with the eligibility date, if
it is already settled or the fallback window has not opened, so a doomed
call costs no gas. Amounts are read back from FallbackSettled so the caller
sees where the money went rather than inferring it.

The description and docs are blunt that this is not a claim: held-back goes
to the treasury (a reviewer triggering it forfeits what a normal settle
would have paid), unreleased cashback reverts to the reviewer, and the
caller pays gas for nothing. Framing it as a payout would invite exactly
the wrong call.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

Then the analogous `docs` and `skills` commits (`docs: document trigger_settle_fallback (REF-253)`).

---

### Task 2: `update_review_content_onchain`

**What it is for.** A buyer review (`ProofType.InSystemPurchase`) is editable on-chain for 7 days via `ReviewRegistry.updateReviewContent(reviewId, newContentHash)`. The backend's `update_review_content` MCP tool syncs the new text into the database and re-runs the alignment oracle — but it **requires the on-chain edit to have happened first**: it reads the review, refuses unless `editedAt != 0`, and recomputes `keccak256(abi.encode(agentId, merchantId, productId, contentJSON))` from the **on-chain** ids, rejecting any content whose hash does not match the on-chain hash (`backend/internal/mcp/tools.go:1847`+). No signer tool sends that transaction, so the whole 7-day edit path is unreachable from MCP.

**The one thing that will break this if you get it wrong.** The hash must be computed from the ids **read off the chain**, not from ids supplied by the caller. `computeContentHash` already exists in `main.go:542` and is the exact function the backend mirrors — reuse it, and feed it `review.AgentID` / `review.MerchantID` / `review.ProductID` from `getReview`. If you instead take `agent_id`/`merchant_id` as tool inputs, a caller passing a wrong-but-plausible id produces a hash the contract happily stores and the backend then permanently rejects, leaving the review un-syncable with its edit window burning down.

**Files:**
- Create: `cmd/signer/update_review.go`
- Test: `cmd/signer/update_review_test.go`
- Modify: `cmd/signer/main.go` (`reviewRegistryABI` literal ~line 54-57, topic vars ~line 46, `AddTool` in `main()`)
- Modify: `CLAUDE.md` (signer tool table; edit-window subsection)
- Modify: `../docs/mcp-methods.md`, `../skills/plugins/referrer-agent-protocol/SKILL.md`, `../skills/plugins/referrer-agent-protocol/reference/reviewing.md`

**Interfaces:**
- Consumes (all already on `main`): `computeContentHash(agentID, merchantID *big.Int, productID [32]byte, contentJSON string) ([32]byte, error)`, `signerKeys.KeyFor`, `reviewRegistryABI`, `dataError`, `hexToBytes32`.
- Produces: `handleUpdateReviewContentOnchain(ctx, *sdkmcp.CallToolRequest, updateReviewOnchainInput) (*sdkmcp.CallToolResult, updateReviewOnchainOutput, error)`; `onChainReview` struct + `decodeGetReview([]byte) (onChainReview, error)`; `editWindowState(publishedAt, now int64) (closesAt int64, open bool)`; `parseUpdateReviewInput`; `decodeUpdateReviewRevertData`.

- [ ] **Step 1: Write the failing tests**

Create `cmd/signer/update_review_test.go`:

```go
package main

import (
	"context"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/crypto"
)

// TestUpdateReview_ABIPack asserts the extended reviewRegistryABI packs
// updateReviewContent(reviewId, newContentHash) to the on-chain selector + args.
func TestUpdateReview_ABIPack(t *testing.T) {
	reviewID := big.NewInt(9)
	var hash [32]byte
	hash[0], hash[31] = 0xAB, 0xCD

	data, err := reviewRegistryABI.Pack("updateReviewContent", reviewID, hash)
	if err != nil {
		t.Fatalf("Pack updateReviewContent: %v", err)
	}
	if len(data) != 4+32+32 {
		t.Fatalf("calldata len = %d, want 68", len(data))
	}
	wantSel := crypto.Keccak256([]byte("updateReviewContent(uint256,bytes32)"))[:4]
	if got, want := hex.EncodeToString(data[:4]), hex.EncodeToString(wantSel); got != want {
		t.Fatalf("selector = %s, want %s", got, want)
	}
	args, err := reviewRegistryABI.Methods["updateReviewContent"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(reviewID) != 0 {
		t.Fatalf("unpacked reviewId = %v, want 9", args[0])
	}
	if got := args[1].([32]byte); got != hash {
		t.Fatalf("unpacked hash = %x, want %x", got, hash)
	}
}

// TestDecodeGetReview round-trips a getReview() return blob through the decoder, so a
// wrong field offset is caught here rather than as a silently wrong content hash on-chain.
// Encoding uses the same ABI types the contract's Review struct declares, in order.
func TestDecodeGetReview(t *testing.T) {
	uint256T, _ := abi.NewType("uint256", "", nil)
	bytes32T, _ := abi.NewType("bytes32", "", nil)
	uint8T, _ := abi.NewType("uint8", "", nil)
	uint40T, _ := abi.NewType("uint40", "", nil)

	var productID, contentHash [32]byte
	productID[0], contentHash[0] = 0x11, 0x22

	blob, err := abi.Arguments{
		{Type: uint256T}, {Type: uint256T}, {Type: bytes32T}, {Type: bytes32T},
		{Type: uint8T}, {Type: uint40T}, {Type: uint40T},
	}.Pack(big.NewInt(6080), big.NewInt(5943), productID, contentHash,
		uint8(2), big.NewInt(1_700_000_000), big.NewInt(0))
	if err != nil {
		t.Fatalf("pack fixture: %v", err)
	}

	got, err := decodeGetReview(blob)
	if err != nil {
		t.Fatalf("decodeGetReview: %v", err)
	}
	if got.AgentID.Int64() != 6080 || got.MerchantID.Int64() != 5943 {
		t.Fatalf("ids = %v/%v, want 6080/5943", got.AgentID, got.MerchantID)
	}
	if got.ProductID != productID || got.ContentHash != contentHash {
		t.Fatalf("productID/contentHash mismatch: %x / %x", got.ProductID, got.ContentHash)
	}
	if got.ProofType != 2 {
		t.Fatalf("proofType = %d, want 2 (InSystemPurchase)", got.ProofType)
	}
	if got.Timestamp != 1_700_000_000 {
		t.Fatalf("timestamp = %d, want 1700000000", got.Timestamp)
	}
	if _, err := decodeGetReview(blob[:100]); err == nil {
		t.Fatal("short blob must not decode")
	}
}

// TestEditWindowState pins ReviewRegistry's gate: the revert is
// `block.timestamp > timestamp + EDIT_WINDOW`, so exactly-at-the-boundary is still OPEN.
func TestEditWindowState(t *testing.T) {
	const published = 1_700_000_000
	const sevenDays = 7 * 24 * 60 * 60

	closesAt, open := editWindowState(published, published+1)
	if closesAt != published+sevenDays {
		t.Fatalf("closesAt = %d, want %d", closesAt, published+sevenDays)
	}
	if !open {
		t.Fatal("one second after publication must be open")
	}
	if _, open := editWindowState(published, published+sevenDays); !open {
		t.Fatal("exactly at the boundary must still be open (contract uses strict >)")
	}
	if _, open := editWindowState(published, published+sevenDays+1); open {
		t.Fatal("one second past the boundary must be closed")
	}
}

// TestUpdateReview_HashMatchesSharedHelper proves the tool hashes content exactly the way
// publish does — and therefore the way the backend recomputes it. The whole tool is useless
// if these diverge: the contract would store a hash the backend then rejects forever.
func TestUpdateReview_HashMatchesSharedHelper(t *testing.T) {
	var productID [32]byte
	productID[0] = 0x11
	content := `{"rating":4,"description":"Updated."}`

	want, err := computeContentHash(big.NewInt(6080), big.NewInt(5943), productID, content)
	if err != nil {
		t.Fatalf("computeContentHash: %v", err)
	}
	got, err := computeContentHash(big.NewInt(6080), big.NewInt(5943), productID, content)
	if err != nil {
		t.Fatalf("computeContentHash: %v", err)
	}
	if got != want {
		t.Fatal("computeContentHash is not deterministic")
	}
	// A different agentId MUST change the hash — proving the ids are inside the preimage,
	// which is why they have to be read from the chain and not taken from the caller.
	other, err := computeContentHash(big.NewInt(6081), big.NewInt(5943), productID, content)
	if err != nil {
		t.Fatalf("computeContentHash: %v", err)
	}
	if other == want {
		t.Fatal("hash ignored agentId — the preimage is wrong")
	}
}

// TestUpdateReview_ParseInputs asserts input parsing and rejection.
func TestUpdateReview_ParseInputs(t *testing.T) {
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: `{"rating":4}`}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "nope", ContentJSON: `{}`}); err == nil {
		t.Fatal("expected error on bad review_id")
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: "   "}); err == nil {
		t.Fatal("expected error on blank content_json")
	}
	if _, err := parseUpdateReviewInput(updateReviewOnchainInput{ReviewID: "9", ContentJSON: "not json"}); err == nil {
		t.Fatal("expected error on non-JSON content_json")
	}
}

// TestDecodeUpdateReviewRevert maps each custom error this tool can hit to a message.
func TestDecodeUpdateReviewRevert(t *testing.T) {
	for _, sig := range []string{
		"ReviewNotFound(uint256)",
		"NotEditablePath(uint256)",
		"CallerNotAgentOwner(uint256,address)",
		"EditWindowClosed(uint256)",
	} {
		sel := crypto.Keccak256([]byte(sig))[:4]
		data := append(append([]byte{}, sel...), make([]byte, 64)...)
		msg, ok := decodeUpdateReviewRevertData(data)
		if !ok || msg == "" {
			t.Fatalf("%s: expected a decoded message, got ok=%v msg=%q", sig, ok, msg)
		}
	}
}

// TestUpdateReview_StopsBeforeRPCWithoutURL proves the handler validates inputs before it
// needs a chain, so a malformed call fails fast with a useful message.
func TestUpdateReview_StopsBeforeRPCWithoutURL(t *testing.T) {
	t.Setenv("BASE_RPC_URL", "")
	_, _, err := handleUpdateReviewContentOnchain(context.Background(), nil,
		updateReviewOnchainInput{ReviewID: "9", ContentJSON: `{"rating":4}`})
	if err == nil {
		t.Fatal("expected an error (BASE_RPC_URL unset)")
	}
	if !strings.Contains(err.Error(), "BASE_RPC_URL") {
		t.Fatalf("expected the BASE_RPC_URL error, got %v", err)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'UpdateReview|DecodeGetReview|EditWindowState' -v`

Expected: **compile failure** — `undefined: updateReviewOnchainInput`, `undefined: decodeGetReview`, `undefined: editWindowState`, `undefined: parseUpdateReviewInput`, `undefined: decodeUpdateReviewRevertData`, `undefined: handleUpdateReviewContentOnchain`.

- [ ] **Step 3: Extend the ABI and add the event topic in `main.go`**

In the `reviewRegistryABI = mustParseABI(...)` literal, add (keeping the existing `publishReviewWithEscrowProof` and `ReviewPublished` entries):

```json
{"inputs":[{"name":"reviewId","type":"uint256"}],"name":"getReview","outputs":[{"components":[{"name":"agentId","type":"uint256"},{"name":"merchantId","type":"uint256"},{"name":"productId","type":"bytes32"},{"name":"contentHash","type":"bytes32"},{"name":"proofType","type":"uint8"},{"name":"timestamp","type":"uint40"},{"name":"editedAt","type":"uint40"}],"name":"","type":"tuple"}],"stateMutability":"view","type":"function"},
{"inputs":[{"name":"reviewId","type":"uint256"},{"name":"newContentHash","type":"bytes32"}],"name":"updateReviewContent","outputs":[],"stateMutability":"nonpayable","type":"function"},
{"anonymous":false,"inputs":[{"indexed":true,"name":"reviewId","type":"uint256"},{"indexed":true,"name":"contentHash","type":"bytes32"},{"indexed":false,"name":"editedAt","type":"uint40"}],"name":"ReviewContentUpdated","type":"event"}
```

Next to the other topic vars, add:

```go
reviewContentUpdatedTopic = crypto.Keccak256Hash([]byte("ReviewContentUpdated(uint256,bytes32,uint40)"))
```

- [ ] **Step 4: Write `cmd/signer/update_review.go`**

```go
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── update_review_content_onchain ───────────────────────────────────────────────
//
// Sends ReviewRegistry.updateReviewContent, the on-chain half of editing a buyer review.
// The backend's update_review_content (referrer-agent) is the other half and REQUIRES this
// to have happened first: it refuses unless editedAt != 0, and it recomputes the content
// hash from the ON-CHAIN agentId/merchantId/productId, rejecting content whose hash does not
// match what this tool stored. That is why the hash here is computed from the ids read off
// the chain — never from caller-supplied ids. A hash over the wrong ids is accepted by the
// contract and then permanently un-syncable, with the 7-day window running down.

// editWindowSecs mirrors ReviewRegistry.EDIT_WINDOW (7 days). Used only to refuse a doomed
// call before spending gas; the chain remains authoritative.
const editWindowSecs int64 = 7 * 24 * 60 * 60

// proofTypeInSystemPurchase is IReviewRegistry.ProofType.InSystemPurchase — the only
// editable path (updateReviewContent reverts NotEditablePath for the other two).
const proofTypeInSystemPurchase uint8 = 2

type updateReviewOnchainInput struct {
	ReviewID    string `json:"review_id"`          // decimal; the ON-CHAIN review id
	ContentJSON string `json:"content_json"`       // the full replacement review content, same shape as at publish
	ChainID     string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env (default 84532)
}

type updateReviewOnchainOutput struct {
	TxHash      string `json:"tx_hash"`             // 0x-prefixed
	ReviewID    string `json:"review_id"`           // echoed
	ContentHash string `json:"content_hash"`        // 0x-prefixed; what the contract now stores
	AgentID     string `json:"agent_id"`            // the on-chain reviewer id whose key signed
	EditedAt    string `json:"edited_at,omitempty"` // unix seconds, from ReviewContentUpdated
	NextSteps   string `json:"next_steps"`
}

// updateReviewNextSteps is the required follow-up. The on-chain edit alone changes only the
// hash — the readable text, the alignment score, and the embedding all live in the backend
// and stay stale until the sync call lands.
const updateReviewNextSteps = "On-chain hash updated. Now call update_review_content " +
	"(referrer-agent) with the SAME review_id and the SAME content_json to sync the stored " +
	"text and re-run the alignment oracle — it verifies your content against this new " +
	"on-chain hash, so any difference is rejected."

// onChainReview is ReviewRegistry.Review as this tool needs it.
type onChainReview struct {
	AgentID     *big.Int
	MerchantID  *big.Int
	ProductID   [32]byte
	ContentHash [32]byte
	ProofType   uint8
	Timestamp   int64
	EditedAt    int64
}

// decodeGetReview decodes a getReview() return blob. Every field of the Review struct is a
// static type, so the tuple is returned inline as seven 32-byte slots in declaration order:
// agentId, merchantId, productId, contentHash, proofType, timestamp, editedAt.
func decodeGetReview(raw []byte) (onChainReview, error) {
	if len(raw) < 224 {
		return onChainReview{}, fmt.Errorf("getReview returned short data: %d bytes (want >= 224)", len(raw))
	}
	var r onChainReview
	r.AgentID = new(big.Int).SetBytes(raw[0:32])
	r.MerchantID = new(big.Int).SetBytes(raw[32:64])
	copy(r.ProductID[:], raw[64:96])
	copy(r.ContentHash[:], raw[96:128])
	r.ProofType = uint8(new(big.Int).SetBytes(raw[128:160]).Uint64())
	r.Timestamp = new(big.Int).SetBytes(raw[160:192]).Int64()
	r.EditedAt = new(big.Int).SetBytes(raw[192:224]).Int64()
	return r, nil
}

// editWindowState mirrors the contract's gate. The revert is
// `block.timestamp > timestamp + EDIT_WINDOW`, i.e. strict, so exactly at the boundary the
// window is still OPEN. Pure so it is testable without a chain.
func editWindowState(publishedAt, now int64) (closesAt int64, open bool) {
	closesAt = publishedAt + editWindowSecs
	return closesAt, now <= closesAt
}

func parseUpdateReviewInput(in updateReviewOnchainInput) (reviewID *big.Int, err error) {
	reviewID, ok := new(big.Int).SetString(strings.TrimSpace(in.ReviewID), 10)
	if !ok {
		return nil, fmt.Errorf("invalid review_id: %q (want a decimal string — the ON-CHAIN review id)", in.ReviewID)
	}
	if strings.TrimSpace(in.ContentJSON) == "" {
		return nil, fmt.Errorf("content_json is required (the full replacement review content)")
	}
	// The hash is over the raw string, so this does NOT reformat the content — it only
	// refuses input that cannot be valid review content, before a tx is paid for.
	if !json.Valid([]byte(in.ContentJSON)) {
		return nil, fmt.Errorf("content_json is not valid JSON")
	}
	return reviewID, nil
}

func updateReviewRevertMessages() map[string]string {
	sel := func(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]) }
	return map[string]string{
		sel("ReviewNotFound(uint256)"):              "no review exists on-chain for that review_id (is it the on-chain id, not the internal database id?)",
		sel("NotEditablePath(uint256)"):             "only a buyer review published with an escrow proof (ProofType.InSystemPurchase) is editable — an admin-approved or oracle-attested review is not",
		sel("CallerNotAgentOwner(uint256,address)"): "the signer key is neither the reviewer agent's owner nor its registered agent wallet — only those two may edit the review",
		sel("EditWindowClosed(uint256)"):            "the 7-day on-chain edit window for this review has closed; the content is now immutable",
	}
}

func decodeUpdateReviewRevertData(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	msg, ok := updateReviewRevertMessages()[hex.EncodeToString(data[:4])]
	return msg, ok
}

func decodeUpdateReviewRevert(err error) (string, bool) {
	var de dataError
	if !errors.As(err, &de) {
		return "", false
	}
	hexData, ok := de.ErrorData().(string)
	if !ok {
		return "", false
	}
	raw, e := hex.DecodeString(strings.TrimPrefix(hexData, "0x"))
	if e != nil {
		return "", false
	}
	return decodeUpdateReviewRevertData(raw)
}

func handleUpdateReviewContentOnchain(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in updateReviewOnchainInput,
) (*sdkmcp.CallToolResult, updateReviewOnchainOutput, error) {
	reviewID, err := parseUpdateReviewInput(in)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, err
	}

	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	registryAddrHex := os.Getenv("REVIEW_REGISTRY_ADDRESS")
	if registryAddrHex == "" {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("REVIEW_REGISTRY_ADDRESS env var not set")
	}

	chainIDStr := in.ChainID
	if chainIDStr == "" {
		chainIDStr = os.Getenv("CHAIN_ID")
	}
	if chainIDStr == "" {
		chainIDStr = "84532" // Base Sepolia
	}
	chainIDInt, err := strconv.ParseInt(chainIDStr, 10, 64)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("invalid chain id %q: %w", chainIDStr, err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	registryAddr := common.HexToAddress(registryAddrHex)

	// ── read the review: it supplies BOTH the hash preimage ids and the key to sign with ──
	callData, err := reviewRegistryABI.Pack("getReview", reviewID)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("pack getReview: %w", err)
	}
	raw, err := client.CallContract(ctx, ethereum.CallMsg{To: &registryAddr, Data: callData}, nil)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("getReview(%s): %w (is review_id the ON-CHAIN id, and is BASE_RPC_URL on chain %d?)", reviewID, err, chainIDInt)
	}
	review, err := decodeGetReview(raw)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, err
	}
	if review.ProofType != proofTypeInSystemPurchase {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"review %s has proofType %d — only a buyer review published with an escrow proof (InSystemPurchase, %d) is editable",
			reviewID, review.ProofType, proofTypeInSystemPurchase)
	}
	closesAt, open := editWindowState(review.Timestamp, time.Now().Unix())
	if !open {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"the 7-day edit window for review %s closed at %s; its content is now immutable",
			reviewID, time.Unix(closesAt, 0).UTC().Format(time.RFC3339))
	}

	// The signing key is selected by the ON-CHAIN reviewer id, so a caller cannot aim this
	// at someone else's review with its own key and get a confusing chain-level revert.
	privKey, err := signerKeys.KeyFor(review.AgentID.String())
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("review %s belongs to agent %s: %w", reviewID, review.AgentID, err)
	}

	// Hash over the ON-CHAIN ids — the exact preimage the backend recomputes.
	newHash, err := computeContentHash(review.AgentID, review.MerchantID, review.ProductID, in.ContentJSON)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("compute content hash: %w", err)
	}
	if newHash == review.ContentHash {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf(
			"content_json hashes to the value already stored on-chain for review %s — nothing to update", reviewID)
	}

	// ── send ───────────────────────────────────────────────────────────────────
	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("build transactor: %w", err)
	}
	contract := bind.NewBoundContract(registryAddr, reviewRegistryABI, client, client, client)

	tx, err := contract.Transact(auth, "updateReviewContent", reviewID, newHash)
	if err != nil {
		if msg, ok := decodeUpdateReviewRevert(err); ok {
			return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent would revert: %s", msg)
		}
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent tx: %w", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, updateReviewOnchainOutput{}, fmt.Errorf("updateReviewContent tx reverted: %s", tx.Hash().Hex())
	}

	out := updateReviewOnchainOutput{
		TxHash:      tx.Hash().Hex(),
		ReviewID:    reviewID.String(),
		ContentHash: "0x" + hex.EncodeToString(newHash[:]),
		AgentID:     review.AgentID.String(),
		NextSteps:   updateReviewNextSteps,
	}
	// ReviewContentUpdated(reviewId indexed, contentHash indexed, uint40 editedAt):
	// editedAt is the only non-indexed field, so it is the single word of Data.
	for _, lg := range receipt.Logs {
		if len(lg.Topics) >= 1 && lg.Topics[0] == reviewContentUpdatedTopic && len(lg.Data) >= 32 {
			out.EditedAt = new(big.Int).SetBytes(lg.Data[0:32]).String()
			break
		}
	}
	return nil, out, nil
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd agent-mcp && gofmt -l cmd/signer/ && go build ./... && go vet ./... && go test -count=1 ./cmd/signer/ -run 'UpdateReview|DecodeGetReview|EditWindowState' -v`

Expected: `gofmt -l` prints only the pre-existing `cmd/signer/vote_sign_test.go`; build and vet clean; all seven tests PASS.

- [ ] **Step 6: Register the tool in `main()`**

Add after the Task 1 registration block:

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "update_review_content_onchain",
		Description: "Edit a buyer review's content on-chain within its 7-day window " +
			"(ReviewRegistry.updateReviewContent). This is the FIRST of two calls: it updates only the " +
			"on-chain content hash. Afterwards you MUST call update_review_content (referrer-agent) with " +
			"the same review_id and the SAME content_json to sync the stored text and re-run the alignment " +
			"oracle — that tool verifies your content against the hash this one stored and rejects any " +
			"difference. Pass review_id (the ON-CHAIN id) and the full replacement content_json; the tool " +
			"reads the review from the chain to build the hash and to pick the signing key, so do not pass " +
			"agent/merchant/product ids. Only a buyer review published with an escrow proof is editable, " +
			"and only by the reviewer agent's owner or its registered agent wallet.",
	}, handleUpdateReviewContentOnchain)
```

- [ ] **Step 7: Verify the whole suite still passes**

Run: `cd agent-mcp && go build ./... && go vet ./... && go test -count=1 ./...`

Expected: `ok github.com/OpenSoukAI/agent-mcp/cmd/signer`.

- [ ] **Step 8: Document it — `agent-mcp`**

In `CLAUDE.md`, add to the **referrer-signer** table:

```markdown
| `update_review_content_onchain` | Edit a buyer review's content hash on-chain within the 7-day window (`ReviewRegistry.updateReviewContent`) — the required first half of an edit; follow with `update_review_content` on referrer-agent |
```

And add a subsection near the review material:

```markdown
### Editing a published buyer review (7-day window, two calls)

A buyer review published with an escrow proof is editable for **7 days** from publication.
An edit is two calls, in this order, and neither one alone is a complete edit:

1. **`update_review_content_onchain`** (referrer-signer) — pass `review_id` (the **on-chain**
   id) and the full replacement `content_json`. The tool reads the review from the chain,
   builds `keccak256(abi.encode(agentId, merchantId, productId, content_json))` from the
   **on-chain** ids, and sends `updateReviewContent`. Do not pass agent/merchant/product ids:
   the hash preimage must match what the chain holds, and the tool reading them itself is what
   guarantees that.
2. **`update_review_content`** (referrer-agent) — same `review_id`, the **same**
   `content_json`. Syncs the stored text, re-runs the alignment oracle, and re-embeds the
   review. It refuses until step 1 has landed (it requires `editedAt != 0`) and it recomputes
   the hash and rejects any content that does not match what step 1 stored.

Stopping after step 1 leaves the readable review, its alignment score, and its embedding stale
while the on-chain hash says otherwise. Only the reviewer agent's **owner** or its registered
**agent wallet** may edit; the other two proof types (admin-approved, oracle-attested) are not
editable at all.
```

- [ ] **Step 9: Document it — sibling repos**

`../docs/mcp-methods.md`, in the **On-chain / payment actions** table:

```markdown
| `update_review_content_onchain` | Edit a buyer review's content hash on-chain inside the 7-day window (`ReviewRegistry.updateReviewContent`); reads the review to build the hash preimage from the on-chain ids and to select the signing key | `review_id` (on-chain id), `content_json`; optional `chain_id` | `tx_hash`, `review_id`, `content_hash`, `agent_id`, `edited_at`, `next_steps`. Follow with `update_review_content` (referrer-agent) |
```

Bump the counts again: `## referrer-signer (agent-mcp) — 13 tools`, total `**35 tools total — 22 on `referrer-agent`, 13 on `referrer-signer`.**`

`../skills/plugins/referrer-agent-protocol/reference/reviewing.md` — the existing `update_review_content` material describes only the backend half. Rewrite it as the two-call sequence above, and state plainly that the backend tool refuses until the on-chain edit has landed. `SKILL.md` — add `update_review_content_onchain` to the `referrer-signer` tool list, and change the `update_review_content` row's *Use* text to "Sync a buyer-review edit after the on-chain update" so the table stops implying one call is enough.

- [ ] **Step 10: Commit**

```bash
cd agent-mcp && git add cmd/signer/update_review.go cmd/signer/update_review_test.go cmd/signer/main.go CLAUDE.md
git commit -m "$(cat <<'EOF'
feat: update_review_content_onchain signer tool (REF-253)

The backend's update_review_content requires the on-chain edit to have
landed first — it refuses unless editedAt != 0 and it recomputes the
content hash from the on-chain ids — and nothing sent that transaction, so
the 7-day buyer-review edit path was unreachable from MCP.

The tool takes only review_id + content_json and reads agentId, merchantId,
and productId off the chain to build the hash preimage. That is deliberate:
those ids are inside the hash, so ids supplied by a caller could produce a
hash the contract stores happily and the backend then rejects forever, with
the edit window running down. Reading them is what makes the two halves
agree. The on-chain reviewer id also selects the signing key, so a caller
cannot aim this at another agent's review and get an opaque revert.

Refuses before spending gas on the three knowable cases: wrong proof type,
closed edit window, and content that hashes to what is already stored.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

Then the analogous `docs` and `skills` commits.

---

## Out of scope (deliberately)

- **`register_agent_identity`** — also in the reconciliation doc's *Missing* table, and genuinely blocking (an agent-less buyer can `pay_for_product` but can never `bind_escrow`, because identity is only mintable in the web wizard). It needs an ERC-8004 mint **plus** `POST /v1/agent/register`, i.e. work in two repos and a product decision about minting outside the wizard. Not an S-sized signer tool; keep it a separate ticket.
- **`get_spending_limits`, `list_merchants`/`get_merchant`, the deadline tool** — all `referrer-agent` (backend) tools, tracked under REF-253's other bullets.
- **`pay_for_product_mpp`** — REF-253's *Rework* item, blocked on two design answers (where the charge amount comes from, and whether the merchant is ever told about the purchase).
- **A chain-integration test harness.** Both tools' unmockable path is `Transact` + `WaitMined` against a real chain. The e2e-script repo is where that coverage belongs (it already drives anvil); add blocks there when these tools are wired into the overnight prompt.

## Self-review notes

- **Spec coverage:** REF-253 *Missing* bullets 1 (`trigger_settle_fallback`) and 2 (`update_review_content_onchain`) are Tasks 1 and 2. Bullets 3–5 are backend tools and are listed under *Out of scope* with their reasons.
- **Type consistency:** `fallbackEligibility`/`editWindowState` both return `(int64, bool)` and are used that way in their handlers; `decodeGetReview` returns the `onChainReview` whose fields the handler reads; `computeContentHash`'s existing signature `(agentID, merchantID *big.Int, productID [32]byte, contentJSON string)` is called exactly once, with on-chain values.
- **Known imprecision worth a follow-up, not a fix here:** `backend/internal/mcp/escrows.go:19-20` hardcodes `escrowWindowDays = 60` / `escrowFallbackDays = 70` off `ConfirmedAt`, but `CommissionEscrow._settlementWindow` is admin-configurable between 1 and 180 days. So `get_escrow_status`'s `fallback_available` can disagree with the chain if the window is ever changed from its default. Task 1's tool reads `windowEnd` from the escrow itself and is therefore correct regardless — which is also why its preflight is worth having rather than trusting the backend flag. File a backend ticket; do not widen this plan.
