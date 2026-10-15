package main

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

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
// opens: `eligibleAt = windowEnd + 10 days + shift` (CommissionEscrow.sol; shift is the pause
// time, added in fallbackEligibility below). Mirrored here only to explain a refusal BEFORE
// spending gas; the chain remains authoritative.
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
	// CashbackFailed / CashbackFailedReviewer / CashbackFailedAmount reflect
	// FallbackCashbackFailed (Sherlock #11/#19): the cashback leg no longer reverts the whole
	// tx on failure, it emits this event instead, so a caller must read it to learn the
	// cashback did not move even though the tx succeeded.
	CashbackFailed         bool   `json:"cashback_failed"`
	CashbackFailedReviewer string `json:"cashback_failed_reviewer,omitempty"`
	CashbackFailedAmount   string `json:"cashback_failed_amount,omitempty"`
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

// fallbackEligibility mirrors the contract's gate: eligibleAt = windowEnd + 10 days + shift,
// where shift is the protocol-pause time accrued since this escrow's deposit (totalPausedSeconds()
// minus the escrow's pausedTotalAtDeposit, clamped at 0 by the caller) — a paused protocol does not
// consume the fallback grace period. The revert is `now < eligibleAt`, so exactly-at-eligibleAt IS
// eligible. Pure so it is testable without a chain.
func fallbackEligibility(windowEnd, shift, now int64) (eligibleAt int64, eligible bool) {
	eligibleAt = windowEnd + fallbackGraceSecs + shift
	return eligibleAt, now >= eligibleAt
}

// fallbackRefusal returns the handler's refusal message for a Settled escrow, or "" if the call
// may proceed. Pure (no chain) so the Sherlock #11/#19 retry rule is testable without a live
// RPC: a Settled escrow whose cashback leg failed (CashbackReleased == false) is a legal retry
// of that leg, not a replay of a finished settlement — only Settled && CashbackReleased (both
// legs paid) is terminal.
func fallbackRefusal(escrowID string, escrow onChainEscrow) string {
	if escrow.State == escrowStateSettled && escrow.CashbackReleased {
		return fmt.Sprintf("escrow %s is already settled — the oracle got there first, nothing is stuck", escrowID)
	}
	return ""
}

// contractCaller is the single method this file needs from *ethclient.Client, declared as an
// interface so totalPausedSeconds's read is testable without a chain (mirrors headerReader in
// chainconn.go).
type contractCaller interface {
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// readTotalPausedSeconds reads CommissionEscrow.totalPausedSeconds(), following the same
// CallContract + revert-table-fallback pattern as the getEscrow preflight below: a read failure
// is returned as an error, never swallowed into a default shift of 0 (which would silently
// under-state eligibleAt).
func readTotalPausedSeconds(ctx context.Context, caller contractCaller, escrowAddr common.Address) (int64, error) {
	callData, err := commissionEscrowABI.Pack("totalPausedSeconds")
	if err != nil {
		return 0, fmt.Errorf("pack totalPausedSeconds: %w", err)
	}
	raw, err := caller.CallContract(ctx, ethereum.CallMsg{To: &escrowAddr, Data: callData}, nil)
	if err != nil {
		if msg, ok := settleFallbackRevertTable.lookupErr(err); ok {
			return 0, fmt.Errorf("totalPausedSeconds(): %s", msg)
		}
		return 0, fmt.Errorf("totalPausedSeconds(): %w", err)
	}
	if len(raw) != 32 {
		return 0, fmt.Errorf("totalPausedSeconds() returned %d bytes, want 32", len(raw))
	}
	return new(big.Int).SetBytes(raw).Int64(), nil
}

// decodeFallbackReceipt reads FallbackSettled and FallbackCashbackFailed (Sherlock #11/#19) from
// the escrow contract's own logs only, ignoring any same-topic log from a different contract.
func decodeFallbackReceipt(out *settleFallbackOutput, logs []*types.Log, escrowAddr common.Address) {
	for _, lg := range logs {
		if lg.Address != escrowAddr {
			continue
		}
		switch {
		// FallbackSettled(escrowId indexed, treasury indexed, uint128 heldBackAmt, uint128 cashbackAmt):
		// both amounts are non-indexed, so they are the two 32-byte words of Data.
		case len(lg.Topics) >= 1 && lg.Topics[0] == fallbackSettledTopic && len(lg.Data) >= 64:
			out.HeldBackToTreasury = new(big.Int).SetBytes(lg.Data[0:32]).String()
			out.CashbackToReviewer = new(big.Int).SetBytes(lg.Data[32:64]).String()
		// FallbackCashbackFailed(escrowId indexed, reviewer indexed, uint128 amount): reviewer is
		// the second indexed topic, amount is the one word of Data.
		case len(lg.Topics) >= 3 && lg.Topics[0] == fallbackCashbackFailedTopic && len(lg.Data) >= 32:
			out.CashbackFailed = true
			out.CashbackFailedReviewer = common.BytesToAddress(lg.Topics[2].Bytes()).Hex()
			out.CashbackFailedAmount = new(big.Int).SetBytes(lg.Data[0:32]).String()
		}
	}
}

// settleFallbackRevertTable maps the custom errors reachable from
// triggerSettleFallback to fallback-specific advice. EnforcedPause is OpenZeppelin v5's
// Pausable error, reachable because the function is `whenNotPaused`. Wording is
// deliberately not shared with bind_escrow's table — see revert.go.
var settleFallbackRevertTable = newRevertTable(map[string]string{
	"AlreadySettled(uint256)":           "this escrow is already settled — the oracle got there first, nothing is stuck",
	"EscrowNotFound(uint256)":           "no escrow found for that escrow_id",
	"TooEarly(uint256,uint256,uint256)": "the public fallback is not open yet — it opens 10 days after the escrow's windowEnd, plus any protocol-pause time since deposit (day ~70 or later)",
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

	keySigner, err := signerKeys.KeyFor(agentID.String())
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}

	client, chainIDInt, err := dialChain(ctx, in.ChainID)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}
	defer client.Close()
	escrowAddr, err := resolveAddress(ctx, chainIDInt, keyEscrow)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}

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
	escrow, err := decodeGetEscrow(raw)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}
	if msg := fallbackRefusal(escrowID.String(), escrow); msg != "" {
		return nil, settleFallbackOutput{}, errors.New(msg)
	}
	// shift mirrors the contract's own gate: a protocol pause after this escrow's deposit does
	// not consume the fallback grace period, so the window shifts out by however long the
	// protocol was paused since deposit. Clamped at 0 because totalPausedSeconds only grows, so
	// a negative value here would only mean this escrow has not yet seen any pause.
	totalPaused, err := readTotalPausedSeconds(ctx, client, escrowAddr)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}
	shift := totalPaused - escrow.PausedTotalAtDeposit
	if shift < 0 {
		shift = 0
	}
	// Judged against the CHAIN's clock, not this process's — see chainNow. Comparing the
	// escrow's on-chain windowEnd against a wall clock is only correct while the two agree.
	now, err := chainNow(ctx, client)
	if err != nil {
		return nil, settleFallbackOutput{}, err
	}
	if eligibleAt, ok := fallbackEligibility(escrow.WindowEnd, shift, now); !ok {
		return nil, settleFallbackOutput{}, fmt.Errorf(
			"escrow %s is not fallback-eligible yet: the public fallback opens at %s (windowEnd + 10 days + %ds of protocol pause); the chain's latest block is at %s",
			escrowID,
			time.Unix(eligibleAt, 0).UTC().Format(time.RFC3339),
			shift,
			time.Unix(now, 0).UTC().Format(time.RFC3339),
		)
	}

	// ── send ───────────────────────────────────────────────────────────────────
	auth := transactOpts(ctx, keySigner, big.NewInt(chainIDInt))
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
		SettledBy: keySigner.Address().Hex(),
	}
	decodeFallbackReceipt(&out, receipt.Logs, escrowAddr)
	return nil, out, nil
}
