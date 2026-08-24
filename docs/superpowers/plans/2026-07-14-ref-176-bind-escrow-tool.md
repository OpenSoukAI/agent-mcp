# REF-176 — `bind_escrow` tool (referrer-signer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `bind_escrow` MCP tool to the referrer-signer that sends `CommissionEscrow.bind(escrowId, agentId)` on-chain from the agent's key and waits for the receipt — completing the agent-less deferred-cashback claim (register identity → **bind escrow** → publish review) entirely through tools, instead of requiring a raw wallet call.

**Architecture:** A send-from-signer tool mirroring the existing `publish_escrow_review` (`handlePublishEscrowReview`): dial `BASE_RPC_URL`, build a keyed transactor from `signerKeys.KeyFor(agentId)`, `bind.NewBoundContract` on the `COMMISSION_ESCROW_ADDRESS` with the (extended) inline `commissionEscrowABI`, `Transact("bind", escrowId, agentId)`, `WaitMined`, check status. Bind is send-only — the backend indexer reacts to the emitted `EscrowBound` event (REF-137); no backend change. Custom-error reverts (`NotBuyerWallet`/`NotAgentController`/`AlreadyBound`) are decoded to friendly messages.

**Tech Stack:** Go, `github.com/ethereum/go-ethereum` (`ethclient`, `accounts/abi`, `accounts/abi/bind`, `common`, `crypto`, `core/types`), `sdkmcp` MCP SDK. Module `github.com/OpenSoukAI/agent-mcp`, signer under `cmd/signer/` (`package main`).

## Global Constraints

- **Repo/branch:** `agent-mcp` → integrates on **`main`** (no `dev`). Branch off `main`; PR targets `main`. (Confirmed in the ticket.)
- **Contract call (exact):** `bind(uint256 escrowId, uint256 agentId)` — selector `0xcadc1f0a`, `nonpayable`, no return, **no `buyerWallet` argument** (the paying-wallet check is against `msg.sender`). Source: backend `internal/chain/contracts/commission_escrow.go:388` + `contracts/src/CommissionEscrow.sol:107-119`.
- **On-chain preconditions (revert reasons the tool must surface):** `NotBuyerWallet(uint256,address)` — `msg.sender` must equal the escrow's recorded `buyerWallet` (the wallet that paid); `NotAgentController(uint256,address)` — `msg.sender` must own `agentId` (`ownerOf`); `AlreadyBound(uint256)` — one-shot; `AlreadySettled(uint256)`; `EscrowNotFound(uint256)`. Success emits `EscrowBound(uint256 indexed escrowId, uint256 indexed agentId, address indexed boundBy)`.
- **Signer key = the paying wallet.** `signerKeys.KeyFor(agentId)` must resolve to the wallet that paid the agent-less purchase AND owns `agentId`, else `bind` reverts. This is a caller/config precondition — document it + surface the revert cleanly. Identity `register()` is OUT OF SCOPE (note the register-first hint in the `NotAgentController` message).
- **Env config (same as `publish_escrow_review`):** `BASE_RPC_URL`, `CHAIN_ID` (default `84532`), `COMMISSION_ESCROW_ADDRESS`. No gas set explicitly — go-ethereum auto-fills nonce/gas.
- **Send-only:** no backend change; the indexer rebinds `purchase_records.buyer_agent_id` off the `EscrowBound` event (REF-137).
- Mirror `handlePublishEscrowReview` (`main.go:562-686`) for the send path; mirror its tool boilerplate for registration.
- Full `go test ./...` green in `agent-mcp` before commit.

## File Structure

- **Modify** `cmd/signer/main.go` — (a) extend the inline `commissionEscrowABI` (`main.go:54-62`, currently only `getEscrow`) to add the `bind` function + the `EscrowBound` event; (b) add one `sdkmcp.AddTool(...)` registration in `main()` after `publish_escrow_review` (~`:1071`).
- **Create** `cmd/signer/bind_escrow.go` — `bindEscrowInput`/`bindEscrowOutput` structs, `handleBindEscrow` (send path), and `decodeBindRevert` (custom-error → friendly message). Reuses `package main` globals `commissionEscrowABI`, `signerKeys`.
- **Create** `cmd/signer/bind_escrow_test.go` — ABI-pack/selector unit test + input-parse test (mirrors `publish_escrow_review` tests; a live send needs anvil → e2e, out of unit scope).
- **Modify** `agent-mcp/CLAUDE.md` — flip the deferred-binding note ("bind is an on-chain action, not an MCP tool") to reference `bind_escrow`.
- **(Flagged, see Task 3)** `agent-mcp/scripts/setup-mcp.sh` — add `COMMISSION_ESCROW_ADDRESS` provisioning (pre-existing gap; blocks the live e2e for `bind_escrow` AND `publish_escrow_review`).

---

### Task 1: `bind_escrow` tool

**Files:**
- Modify: `cmd/signer/main.go` (extend `commissionEscrowABI` ~`:54-62`; add `AddTool` in `main()` ~`:1071`)
- Create: `cmd/signer/bind_escrow.go`
- Create: `cmd/signer/bind_escrow_test.go`

**Interfaces:**
- Consumes (existing `package main` symbols): `commissionEscrowABI` (main.go:54), `signerKeys` + `signerKeys.KeyFor` (main.go:252). Reuses env vars `BASE_RPC_URL`/`CHAIN_ID`/`COMMISSION_ESCROW_ADDRESS`.
- Produces: `handleBindEscrow(context.Context, *sdkmcp.CallToolRequest, bindEscrowInput) (*sdkmcp.CallToolResult, bindEscrowOutput, error)`; the `bind_escrow` tool.

- [ ] **Step 1: Extend `commissionEscrowABI` in `main.go`**

In `cmd/signer/main.go`, the `commissionEscrowABI = mustParseABI(` ... `)` block (`:54-62`) currently contains only the `getEscrow` entry. Add the `bind` function and the `EscrowBound` event to the JSON array (keep `getEscrow` unchanged):

```json
{"inputs":[{"name":"escrowId","type":"uint256"},{"name":"agentId","type":"uint256"}],"name":"bind","outputs":[],"stateMutability":"nonpayable","type":"function"},
{"anonymous":false,"inputs":[{"indexed":true,"name":"escrowId","type":"uint256"},{"indexed":true,"name":"agentId","type":"uint256"},{"indexed":true,"name":"boundBy","type":"address"}],"name":"EscrowBound","type":"event"}
```

(These two entries go inside the same `[...]` passed to `mustParseABI`, comma-separated with the existing `getEscrow` entry.)

- [ ] **Step 2: Write the failing tests**

Create `cmd/signer/bind_escrow_test.go`:

```go
package main

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// TestBindEscrow_ABIPack asserts the extended commissionEscrowABI packs bind(escrowId, agentId)
// to the correct 4-byte selector + args (the on-chain call the tool sends). Selector for
// bind(uint256,uint256) is 0xcadc1f0a (backend commission_escrow.go).
func TestBindEscrow_ABIPack(t *testing.T) {
	escrowID := big.NewInt(42)
	agentID := big.NewInt(7)

	data, err := commissionEscrowABI.Pack("bind", escrowID, agentID)
	if err != nil {
		t.Fatalf("Pack bind: %v", err)
	}
	if len(data) != 4+32+32 {
		t.Fatalf("calldata len = %d, want 68", len(data))
	}
	// Selector = keccak256("bind(uint256,uint256)")[:4]; assert it matches the on-chain selector.
	wantSel := crypto.Keccak256([]byte("bind(uint256,uint256)"))[:4]
	if got := hex.EncodeToString(data[:4]); got != hex.EncodeToString(wantSel) {
		t.Fatalf("selector = %s, want %s", got, hex.EncodeToString(wantSel))
	}
	if hex.EncodeToString(data[:4]) != "cadc1f0a" {
		t.Fatalf("selector = %s, want cadc1f0a", hex.EncodeToString(data[:4]))
	}
	// Round-trip the args back out.
	args, err := commissionEscrowABI.Methods["bind"].Inputs.Unpack(data[4:])
	if err != nil {
		t.Fatalf("Unpack: %v", err)
	}
	if args[0].(*big.Int).Cmp(escrowID) != 0 || args[1].(*big.Int).Cmp(agentID) != 0 {
		t.Fatalf("unpacked args = %v, want [42 7]", args)
	}
}

// TestBindEscrow_ParseInputs asserts decimal-string inputs parse to big.Int and reject garbage.
func TestBindEscrow_ParseInputs(t *testing.T) {
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "42", AgentID: "7"}); err != nil {
		t.Fatalf("valid parse: %v", err)
	}
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "notanumber", AgentID: "7"}); err == nil {
		t.Fatal("expected error on bad escrow_id")
	}
	if _, _, err := parseBindInputs(bindEscrowInput{EscrowID: "42", AgentID: ""}); err == nil {
		t.Fatal("expected error on empty agent_id")
	}
}

// TestDecodeBindRevert maps a known custom-error selector to a friendly message.
func TestDecodeBindRevert(t *testing.T) {
	sel := crypto.Keccak256([]byte("AlreadyBound(uint256)"))[:4]
	// revert data = selector + abi-encoded uint256 arg (value irrelevant to the selector match)
	data := append(append([]byte{}, sel...), make([]byte, 32)...)
	msg, ok := decodeBindRevertData(data)
	if !ok || msg == "" {
		t.Fatalf("expected AlreadyBound decode, got ok=%v msg=%q", ok, msg)
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'TestBindEscrow|TestDecodeBindRevert' -v`
Expected: FAIL to compile — `bindEscrowInput`, `parseBindInputs`, `decodeBindRevertData` undefined (and `bind`/Pack may fail until Step 1's ABI entry is added — do Step 1 first if the pack line errors).

- [ ] **Step 4: Implement `cmd/signer/bind_escrow.go`**

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

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

type bindEscrowInput struct {
	AgentID  string `json:"agent_id"`            // decimal; the agent's own ERC-8004 id (owned by the paying wallet)
	EscrowID string `json:"escrow_id"`           // decimal; from pay_for_product output / list_escrows backlog
	ChainID  string `json:"chain_id,omitempty"`  // optional; overrides CHAIN_ID env (default 84532). BASE_RPC_URL must point at this chain.
}

type bindEscrowOutput struct {
	TxHash   string `json:"tx_hash"`   // 0x-prefixed
	EscrowID string `json:"escrow_id"` // echoed
	AgentID  string `json:"agent_id"`  // echoed
	BoundBy  string `json:"bound_by"`  // = signer address (msg.sender == EscrowBound.boundBy)
}

func parseBindInputs(in bindEscrowInput) (escrowID, agentID *big.Int, err error) {
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

// bindRevertMessages maps a CommissionEscrow custom-error selector (hex, 4 bytes) to a
// caller-facing explanation. Selectors are computed at runtime from the error signatures so
// there is no hand-copied hex to drift.
func bindRevertMessages() map[string]string {
	sel := func(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]) }
	return map[string]string{
		sel("NotBuyerWallet(uint256,address)"):    "the signer key is not the wallet that paid for this escrow — bind must be sent from the exact wallet that made the agent-less purchase",
		sel("NotAgentController(uint256,address)"): "the signer wallet does not own agent_id — register the ERC-8004 identity from the paying wallet first (register() is out of scope for this tool)",
		sel("AlreadyBound(uint256)"):               "this escrow is already bound to an agent (bind is one-shot)",
		sel("AlreadySettled(uint256)"):             "this escrow is already settled — too late to bind",
		sel("EscrowNotFound(uint256)"):             "no escrow found for that escrow_id",
	}
}

// dataError is the interface go-ethereum's RPC errors implement to expose revert data.
type dataError interface{ ErrorData() interface{} }

func decodeBindRevertData(data []byte) (string, bool) {
	if len(data) < 4 {
		return "", false
	}
	msg, ok := bindRevertMessages()[hex.EncodeToString(data[:4])]
	return msg, ok
}

// decodeBindRevert extracts revert data from a go-ethereum tx/estimate error and maps its
// custom-error selector to a friendly message. Returns ("", false) if it can't decode one.
func decodeBindRevert(err error) (string, bool) {
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
	return decodeBindRevertData(raw)
}

func handleBindEscrow(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in bindEscrowInput,
) (*sdkmcp.CallToolResult, bindEscrowOutput, error) {
	escrowID, agentID, err := parseBindInputs(in)
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}

	privKey, err := signerKeys.KeyFor(in.AgentID)
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}

	rpcURL := os.Getenv("BASE_RPC_URL")
	if rpcURL == "" {
		return nil, bindEscrowOutput{}, fmt.Errorf("BASE_RPC_URL env var not set")
	}
	escrowAddrHex := os.Getenv("COMMISSION_ESCROW_ADDRESS")
	if escrowAddrHex == "" {
		return nil, bindEscrowOutput{}, fmt.Errorf("COMMISSION_ESCROW_ADDRESS env var not set")
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
		return nil, bindEscrowOutput{}, fmt.Errorf("invalid chain id %q: %w", chainIDStr, err)
	}

	client, err := ethclient.DialContext(ctx, rpcURL)
	if err != nil {
		return nil, bindEscrowOutput{}, fmt.Errorf("dial rpc: %w", err)
	}
	defer client.Close()

	auth, err := bind.NewKeyedTransactorWithChainID(privKey, big.NewInt(chainIDInt))
	if err != nil {
		return nil, bindEscrowOutput{}, fmt.Errorf("build transactor: %w", err)
	}

	escrowAddr := common.HexToAddress(escrowAddrHex)
	contract := bind.NewBoundContract(escrowAddr, commissionEscrowABI, client, client, client)

	tx, err := contract.Transact(auth, "bind", escrowID, agentID)
	if err != nil {
		if msg, ok := decodeBindRevert(err); ok {
			return nil, bindEscrowOutput{}, fmt.Errorf("bind would revert: %s", msg)
		}
		return nil, bindEscrowOutput{}, fmt.Errorf("bind tx: %w (check: is the signer key the wallet that paid this escrow, does it own agent_id, and is the escrow still unbound?)", err)
	}

	receipt, err := bind.WaitMined(ctx, client, tx)
	if err != nil {
		return nil, bindEscrowOutput{}, fmt.Errorf("wait mined: %w", err)
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, bindEscrowOutput{}, fmt.Errorf("bind tx reverted: %s (check: signer wallet paid this escrow? owns agent_id? escrow not already bound?)", tx.Hash().Hex())
	}

	boundBy := crypto.PubkeyToAddress(privKey.PublicKey)
	return nil, bindEscrowOutput{
		TxHash:   tx.Hash().Hex(),
		EscrowID: escrowID.String(),
		AgentID:  agentID.String(),
		BoundBy:  boundBy.Hex(),
	}, nil
}
```

> Notes: (1) `BoundBy` is derived from the signer key = `msg.sender` = the `EscrowBound.boundBy` indexed field; a successful `receipt.Status` means the event emitted, so we don't decode logs. (2) The `EscrowBound` event was added to the ABI (Step 1) for completeness/future log decoding. (3) If the compiler flags any import unused after your final code, trim it.

- [ ] **Step 5: Register the tool in `main()`**

In `cmd/signer/main.go`, immediately after the `publish_escrow_review` `AddTool` (~`:1071`), add:

```go
	sdkmcp.AddTool(srv, &sdkmcp.Tool{
		Name: "bind_escrow",
		Description: "Bind an agent-less purchase's escrow to your ERC-8004 agent identity by sending " +
			"CommissionEscrow.bind(escrowId, agentId) on-chain with the agent's key, unlocking the deferred " +
			"cashback + enabling the deferred review. PRECONDITION: the signer key MUST be the exact wallet " +
			"that paid the agent-less purchase AND must already own agent_id (register the identity first). " +
			"Inputs: escrow_id (from pay_for_product / list_escrows), agent_id. After it succeeds, the backend " +
			"rebinds the purchase automatically; then call publish_escrow_review + register_purchase_review.",
	}, handleBindEscrow)
```

- [ ] **Step 6: Run tests + full suite**

Run: `cd agent-mcp && go test ./cmd/signer/ -run 'TestBindEscrow|TestDecodeBindRevert' -v && go build ./... && go vet ./... && go test ./...`
Expected: the three new tests PASS; full suite green.

- [ ] **Step 7: Commit**

```bash
cd agent-mcp && go test ./... && \
git add cmd/signer/bind_escrow.go cmd/signer/bind_escrow_test.go cmd/signer/main.go && \
git commit -m "feat(signer): bind_escrow tool — send CommissionEscrow.bind for agent-less claim (REF-176)"
```
(End the commit body with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.)

---

### Task 2: Runbook update (`agent-mcp/CLAUDE.md`)

**Files:**
- Modify: `agent-mcp/CLAUDE.md` (the deferred-binding / agent-less-claim section)

- [ ] **Step 1: Update the deferred-binding note**

Find the sentence in `agent-mcp/CLAUDE.md` stating that bind is "an on-chain action, not an MCP tool" (per the ticket). Replace it so the documented claim sequence references the new tool, e.g.:

> Agent-less deferred claim: `pay_for_product` (agent-less) → register ERC-8004 identity (once, from the paying wallet — not yet a tool) → **`bind_escrow`** (`escrow_id`, `agent_id`) → `publish_escrow_review` → `register_purchase_review`. `bind_escrow` sends `CommissionEscrow.bind` from the agent's key; the signer key must be the wallet that paid and must own `agent_id`.

Match the file's existing wording/format; keep the "identity registration is still wallet-native (no tool yet)" caveat.

- [ ] **Step 2: Commit**

```bash
cd agent-mcp && git add CLAUDE.md && \
git commit -m "docs(signer): reference bind_escrow in the deferred-binding runbook (REF-176)"
```
(+ trailer.)

---

### Task 3 (FLAGGED — controller decision): `setup-mcp.sh` — provision `COMMISSION_ESCROW_ADDRESS`

**Why flagged:** the ticket does NOT list this, but the investigation found `agent-mcp/scripts/setup-mcp.sh` (`SIGNER_ENV`, ~line 67) sets only `BASE_RPC_URL`/`REVIEW_REGISTRY_ADDRESS`/`CHAIN_ID` — it never sets `COMMISSION_ESCROW_ADDRESS`. So `bind_escrow` (and the **already-shipped** `publish_escrow_review`, which also reads it) are non-functional in the live stack. The ticket's "Verification → live e2e (Block R)" cannot pass without it. This touches shared setup infra and fixes a pre-existing gap in another tool.

**Decision for the human:** do this here (unblocks the live e2e for both tools) or split to its own follow-up ticket? Recommended: do it here — small, and REF-176's own verification needs it.

**If done here:**
- Modify: `agent-mcp/scripts/setup-mcp.sh`

- [ ] **Step 1: Resolve `COMMISSION_ESCROW` from PAR + add to `SIGNER_ENV`**

The script already resolves `REVIEW_REGISTRY` from the ProtocolAddressRegistry via `cast keccak "REVIEW_REGISTRY"` → `getAddress(bytes32)` (~lines 47-49). Add an analogous resolution for the commission escrow and append it to `SIGNER_ENV` (~line 67). **VERIFY the exact PAR key string** against the contract's key constant before trusting `cast keccak "COMMISSION_ESCROW"` — check `contracts/src/ProtocolAddressRegistry.sol` (or wherever the key constants are defined) for the canonical key name (e.g. `COMMISSION_ESCROW` vs `ESCROW`); use the verified string. Then:

```bash
COMMISSION_ESCROW_ADDRESS=$(cast call "$PAR_ADDRESS" "getAddress(bytes32)(address)" "$(cast keccak "<VERIFIED_PAR_KEY>")" --rpc-url "$BASE_RPC_URL")
# ... then add to SIGNER_ENV:
SIGNER_ENV=(-e "BASE_RPC_URL=$BASE_RPC_URL" -e "REVIEW_REGISTRY_ADDRESS=$REVIEW_REGISTRY_ADDRESS" -e "COMMISSION_ESCROW_ADDRESS=$COMMISSION_ESCROW_ADDRESS" -e "CHAIN_ID=$CHAIN_ID")
```

Match the script's existing resolution style (variable names, error-if-zero-address handling if present).

- [ ] **Step 2: Verify + commit**

Run the setup script against the local anvil stack (or dry-run the resolution) and confirm `COMMISSION_ESCROW_ADDRESS` resolves to a non-zero address.
```bash
cd agent-mcp && git add scripts/setup-mcp.sh && \
git commit -m "fix(setup): provision COMMISSION_ESCROW_ADDRESS for the signer (REF-176)"
```
(+ trailer.)

---

## Self-Review

**Spec coverage (REF-176):**
- `bind_escrow` sends `bind(escrowId, agentId)` from the agent key + waits receipt + returns tx_hash + EscrowBound result → Task 1 ✓
- Input `escrow_id`, `agent_id`, optional `chain_id` → `bindEscrowInput` ✓
- Mirrors `publish_escrow_review` send path + reuses `commissionEscrowABI` (extended with `bind`) → Task 1 Steps 1,4 ✓
- Surfaces `NotBuyerWallet`/`NotAgentController`/`AlreadyBound` cleanly; register-first hint on the agent-controller error → `decodeBindRevert` + messages ✓
- Precondition (signer key = paying wallet, must own agentId) documented in tool description + error text ✓
- Send-only, no backend change → confirmed (Global Constraints) ✓
- Runbook update → Task 2 ✓
- Unit test on ABI pack of bind mirroring publish_escrow_review tests → Task 1 Step 2 ✓
- Repo → main → Global Constraints ✓
- Live e2e (Block R) → needs `COMMISSION_ESCROW_ADDRESS` provisioning → Task 3 (flagged) ✓

**Placeholder scan:** Task 3's PAR key string (`<VERIFIED_PAR_KEY>`) is an explicit derive-and-verify step (check the contract's key constant), not a silent TODO — it must be confirmed against `ProtocolAddressRegistry` before use. No other placeholders.

**Type consistency:** `bindEscrowInput.{AgentID,EscrowID,ChainID}` (strings) → `parseBindInputs` → `*big.Int` → `commissionEscrowABI.Pack("bind", escrowID, agentID)` / `contract.Transact(auth,"bind",escrowID,agentID)`. `signerKeys.KeyFor(in.AgentID)` takes the decimal string (matches the sibling `publish_escrow_review`, which passes `in.AgentID` string). `decodeBindRevert`/`decodeBindRevertData`/`bindRevertMessages` names consistent across code + tests.

**Gaps / decisions surfaced (not silently dropped):**
- **Task 3 is a controller decision** (fix the setup gap here vs follow-up ticket) — blocks live e2e for `bind_escrow` AND `publish_escrow_review`.
- **No client-side wallet-match precheck:** nothing tells the agent the escrow's `buyerWallet`, so a wrong-wallet bind fails only on-chain (`NotBuyerWallet`) — which the tool now decodes to a clear message. Acceptable; noted.
- **Custom-error decode is best-effort:** if a future go-ethereum version changes how revert data is exposed, `decodeBindRevert` falls back to the generic error+hint (never silently swallows). The `receipt.Status` revert path also carries the precondition hint.
- **Identity `register()` remains wallet-native** (out of scope per ticket) — surfaced in the `NotAgentController` message + tool description.

## Out of scope
- `IdentityRegistry.register()` tool (companion gap — possible follow-up).
- Backend changes (the indexer already reacts to `EscrowBound`, REF-137).
- The "bind-in-publish merge" optimization (spec C-4 — later).
