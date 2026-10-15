package main

import (
	"context"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/core/types"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// ── bind_escrow ─────────────────────────────────────────────────────────────────

type bindEscrowInput struct {
	AgentID  string `json:"agent_id"`           // decimal; the agent's own ERC-8004 id (owned by the paying wallet)
	EscrowID string `json:"escrow_id"`          // decimal; from pay_for_product output / list_escrows backlog
	ChainID  string `json:"chain_id,omitempty"` // optional; overrides CHAIN_ID env (default 84532). BASE_RPC_URL must point at this chain.
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

// bindRevertTable maps the CommissionEscrow custom errors reachable from bind() to
// bind-specific advice. Wording is deliberately not shared with settle_fallback's table:
// the same AlreadySettled/EscrowNotFound selectors mean something different to a caller
// trying to bind than to one forcing a settle. See revert.go.
var bindRevertTable = newRevertTable(map[string]string{
	"NotBuyerWallet(uint256,address)":     "the signer key is not the wallet that paid for this escrow — bind must be sent from the exact wallet that made the agent-less purchase",
	"NotAgentController(uint256,address)": "the signer wallet does not own agent_id — register the ERC-8004 identity from the paying wallet first (register() is out of scope for this tool)",
	"AlreadyBound(uint256)":               "this escrow is already bound to an agent (bind is one-shot)",
	"AlreadySettled(uint256)":             "this escrow is already settled — too late to bind",
	"EscrowNotFound(uint256)":             "no escrow found for that escrow_id",
})

func handleBindEscrow(
	ctx context.Context,
	_ *sdkmcp.CallToolRequest,
	in bindEscrowInput,
) (*sdkmcp.CallToolResult, bindEscrowOutput, error) {
	escrowID, agentID, err := parseBindInputs(in)
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}

	keySigner, err := signerKeys.KeyFor(agentID.String())
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}

	client, chainIDInt, err := dialChain(ctx, in.ChainID)
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}
	defer client.Close()
	escrowAddr, err := resolveAddress(ctx, chainIDInt, keyEscrow)
	if err != nil {
		return nil, bindEscrowOutput{}, err
	}

	auth := transactOpts(ctx, keySigner, big.NewInt(chainIDInt))

	contract := bind.NewBoundContract(escrowAddr, commissionEscrowABI, client, client, client)

	tx, err := contract.Transact(auth, "bind", escrowID, agentID)
	if err != nil {
		if msg, ok := bindRevertTable.lookupErr(err); ok {
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

	boundBy := keySigner.Address()
	return nil, bindEscrowOutput{
		TxHash:   tx.Hash().Hex(),
		EscrowID: escrowID.String(),
		AgentID:  agentID.String(),
		BoundBy:  boundBy.Hex(),
	}, nil
}
