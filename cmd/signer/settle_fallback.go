package main

import (
	"context"
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

// decodeEscrowWindowEndAndState pulls windowEnd and state out of getEscrow's raw ABI-encoded
// return. All 13 EscrowRecord fields are static types, one 32-byte word each, in declaration
// order: reviewerAgentId, buyerAgentId, buyerWallet, merchantId, productId, heldBackAmt,
// cashbackAmt, originalPurchaseAmt, depositTimestamp, windowEnd, productType, state,
// cashbackReleased. windowEnd is word 9 (bytes 288:320); state is word 11 (bytes 352:384).
// Pure and unit-tested against a synthetic tuple so a future struct-field reorder (in this
// file or a later contract version) fails a test instead of silently misreading a live chain.
func decodeEscrowWindowEndAndState(raw []byte) (windowEnd, state int64, err error) {
	if len(raw) < 384 {
		return 0, 0, fmt.Errorf("getEscrow returned short data: %d bytes", len(raw))
	}
	windowEnd = new(big.Int).SetBytes(raw[288:320]).Int64()
	state = new(big.Int).SetBytes(raw[352:384]).Int64()
	return windowEnd, state, nil
}

// settleFallbackRevertTable maps the custom errors reachable from
// triggerSettleFallback to fallback-specific advice. EnforcedPause is OpenZeppelin v5's
// Pausable error, reachable because the function is `whenNotPaused`. Wording is
// deliberately not shared with bind_escrow's table — see revert.go.
var settleFallbackRevertTable = newRevertTable(map[string]string{
	"AlreadySettled(uint256)":           "this escrow is already settled — the oracle got there first, nothing is stuck",
	"EscrowNotFound(uint256)":           "no escrow found for that escrow_id",
	"TooEarly(uint256,uint256,uint256)": "the public fallback is not open yet — it opens 10 days after the escrow's windowEnd (day ~70)",
	"EnforcedPause()":                   "CommissionEscrow is paused by the protocol admin — no settlement of any kind can run until it is unpaused",
})

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
	callData, err := commissionEscrowABI.Pack("getEscrow", escrowID)
	if err != nil {
		return nil, settleFallbackOutput{}, fmt.Errorf("pack getEscrow: %w", err)
	}
	raw, err := client.CallContract(ctx, ethereum.CallMsg{To: &escrowAddr, Data: callData}, nil)
	if err != nil {
		if msg, ok := settleFallbackRevertTable.lookupErr(err); ok {
			return nil, settleFallbackOutput{}, fmt.Errorf("getEscrow(%s): %s", escrowID, msg)
		}
		return nil, settleFallbackOutput{}, fmt.Errorf("getEscrow(%s): %w (is escrow_id right, and is BASE_RPC_URL on chain %d?)", escrowID, err, chainIDInt)
	}
	windowEnd, state, err := decodeEscrowWindowEndAndState(raw)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}
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
		if msg, ok := settleFallbackRevertTable.lookupErr(err); ok {
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
