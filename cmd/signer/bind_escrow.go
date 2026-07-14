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

// bindRevertMessages maps a CommissionEscrow custom-error selector (hex, 4 bytes) to a
// caller-facing explanation. Selectors are computed at runtime from the error signatures so
// there is no hand-copied hex to drift.
func bindRevertMessages() map[string]string {
	sel := func(sig string) string { return hex.EncodeToString(crypto.Keccak256([]byte(sig))[:4]) }
	return map[string]string{
		sel("NotBuyerWallet(uint256,address)"):     "the signer key is not the wallet that paid for this escrow — bind must be sent from the exact wallet that made the agent-less purchase",
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

	privKey, err := signerKeys.KeyFor(agentID.String())
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
